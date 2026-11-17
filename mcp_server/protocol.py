"""
V380 Camera Protocol Implementation
Based on REA/Ghidra analysis of libhsMediaLibrary.so, libhsUtils.so, libnms.so

Key findings:
- Transport: UDP for video, TCP for control (mr_tcp_connect)
- Session: MQTT-based key exchange + token refresh
- Encryption: AES via iotc_ms_frame_cipher_* (media_data_encrypt/decrypt)
- PTZ: setPTZParam (11 params) / setPTZXParam (3 params)
- Video: startPlay -> frames via callbackPreviewRes
- Discovery: Not NVDEVSEARCH^100 - uses MQTT/P2P via callbackMqErrorStartP2p
"""
import os
import json
import socket
import struct
import threading
import time
import logging
import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Callable
from enum import IntEnum
from queue import Queue, Empty
import base64

logger = logging.getLogger(__name__)


class CommandCode(IntEnum):
    """V380 command codes from native analysis."""
    # Session management
    REFRESH_TOKEN = 0x1001
    REFRESH_SESSION = 0x1002
    KEY_EXCHANGE = 0x1003
    
    # Video streaming
    START_PLAY = 0x2001
    STOP_PLAY = 0x2002
    START_PLAYBACK = 0x2003
    STOP_PLAYBACK = 0x2004
    GET_SNAPSHOT = 0x2005
    
    # PTZ control
    PTZ_PARAM = 0x3001      # setPTZParam (11 params)
    PTZ_X_PARAM = 0x3002    # setPTZXParam (3 params)
    PTZ_PRESET = 0x3003
    PTZ_CRUISE = 0x3004
    
    # Audio
    START_SPEAK = 0x4001
    STOP_SPEAK = 0x4002
    SEND_AUDIO = 0x4003
    
    # Keep-alive
    HEARTBEAT = 0x5001


class FrameType(IntEnum):
    """Video frame types from isFrameType/isDataKeyFrame."""
    I_FRAME = 0
    P_FRAME = 2
    IDR_FRAME = 9
    SPS_PPS = 36
    SEI = 40
    AUD = 50
    FILLER = 52


KEY_FRAME_TYPES = {0, 2, 9, 36, 40, 50, 52}


@dataclass
class CameraConfig:
    """Camera configuration from environment."""
    ip: str = os.getenv("CAMERA_IP", "192.168.1.169")
    port: int = int(os.getenv("CAMERA_PORT", "5050"))
    uid: str = os.getenv("CAMERA_ID", "")
    username: str = os.getenv("CAMERA_USER", "admin")
    password: str = os.getenv("CAMERA_PASS", "")
    use_ssl: bool = os.getenv("CAMERA_SSL", "false").lower() == "true"


@dataclass
class SessionState:
    """Active session state."""
    handle: int = 0
    device_id: int = 0
    session_id: int = 0
    session_key: bytes = b""  # 16 bytes AES key
    session_iv: bytes = b""   # 16 bytes IV
    token: str = ""
    token_expiry: float = 0
    p2p_mode: bool = False
    last_heartbeat: float = 0
    sequence: int = 0


@dataclass
class FrameHeader:
    """Video frame header (20 bytes from FIFO queue analysis)."""
    offset: int
    size: int
    frame_type: int
    flags1: int
    flags2: int
    ts_low: int
    ts_high: int

    @classmethod
    def parse(cls, data: bytes) -> "FrameHeader":
        if len(data) < 20:
            raise ValueError("Frame header too short")
        offset, size, ftype, f1, f2, ts_low, ts_high = struct.unpack("<IIBBBII", data[:20])
        return cls(offset, size, ftype, f1, f2, ts_low, ts_high)

    def is_key_frame(self) -> bool:
        return self.frame_type in KEY_FRAME_TYPES


class V380ProtocolClient:
    """
    Low-level V380 camera protocol client.
    Implements the protocol discovered via REA analysis of native libraries.
    """
    
    def __init__(self, config: CameraConfig):
        self.config = config
        self.session = SessionState()
        self._tcp_sock: Optional[socket.socket] = None
        self._udp_sock: Optional[socket.socket] = None
        self._running = False
        self._recv_thread: Optional[threading.Thread] = None
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._frame_queue: Queue = Queue(maxsize=50)
        self._callbacks: Dict[str, Callable] = {}
        self._lock = threading.Lock()
        
    def connect(self, timeout: float = 10.0) -> bool:
        """Establish connection to camera."""
        logger.info(f"Connecting to camera at {self.config.ip}:{self.config.port}")
        
        try:
            # TCP connection for control channel (mr_tcp_connect equivalent)
            self._tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._tcp_sock.settimeout(timeout)
            self._tcp_sock.connect((self.config.ip, self.config.port))
            
            # UDP socket for video stream
            self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp_sock.settimeout(1.0)
            self._udp_sock.bind(("", 0))  # Bind to any local port
            
            # Perform login/key exchange
            if not self._login():
                return False
            
            # Start receive loop
            self._running = True
            self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
            self._recv_thread.start()
            
            # Start heartbeat
            self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
            self._heartbeat_thread.start()
            
            logger.info("Camera connection established")
            return True
            
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            self.disconnect()
            return False
    
    def _login(self) -> bool:
        """Perform login and key exchange (equivalent to LoginHelper.login + MQTT key exchange)."""
        # Based on analysis:
        # 1. LoginHelper.login(context, deviceInfo, 5) for P2P
        # 2. Key exchange via LoginHelper.keyExchangeFromMqSync or keyExchangeByLanSync
        # 3. Session token refresh via refreshIpPortHandleToken / refreshMqKeyExchangeInfo
        
        try:
            # Build login request
            login_req = {
                "cmd": CommandCode.KEY_EXCHANGE,
                "seq": self._next_seq(),
                "params": {
                    "username": self.config.username,
                    "password": self.config.password,
                    "device_id": self.config.uid,
                    "client_type": "mcp_server",
                },
                "auth": {}
            }
            
            resp = self._send_tcp_command(login_req)
            if not resp or resp.get("ret") != 0:
                logger.error(f"Login failed: {resp}")
                return False
            
            # Parse session data
            data = resp.get("data", {})
            self.session.handle = data.get("handle", 0)
            self.session.device_id = data.get("device_id", 0)
            self.session.session_id = data.get("sid", 0)
            self.session.token = data.get("token", "")
            self.session.session_key = base64.b64decode(data.get("skey", ""))
            self.session.session_iv = base64.b64decode(data.get("iv", ""))
            self.session.token_expiry = time.time() + data.get("expires_in", 3600)
            
            logger.info(f"Login successful, handle={self.session.handle}, sid={self.session.session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            return False
    
    def _send_tcp_command(self, cmd: dict, timeout: float = 5.0) -> Optional[dict]:
        """Send command over TCP control channel."""
        if not self._tcp_sock:
            return None
        
        with self._lock:
            try:
                # Add sequence and auth
                cmd["seq"] = self._next_seq()
                if self.session.token:
                    cmd["auth"] = {"token": self.session.token, "sid": self.session.session_id}
                
                # Send
                data = json.dumps(cmd).encode("utf-8")
                # Simple length-prefixed framing
                header = struct.pack(">I", len(data))
                self._tcp_sock.sendall(header + data)
                
                # Receive response
                self._tcp_sock.settimeout(timeout)
                resp_header = self._recv_exact(4)
                if not resp_header:
                    return None
                resp_len = struct.unpack(">I", resp_header)[0]
                resp_data = self._recv_exact(resp_len)
                if not resp_data:
                    return None
                
                return json.loads(resp_data.decode("utf-8"))
                
            except Exception as e:
                logger.error(f"TCP command error: {e}")
                return None
    
    def _recv_exact(self, n: int) -> Optional[bytes]:
        """Receive exactly n bytes."""
        data = b""
        while len(data) < n:
            chunk = self._tcp_sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def _next_seq(self) -> int:
        with self._lock:
            self.session.sequence += 1
            return self.session.sequence
    
    def _recv_loop(self):
        """Background thread to receive UDP video frames and TCP responses."""
        while self._running:
            try:
                # Check UDP for video frames
                if self._udp_sock:
                    try:
                        data, addr = self._udp_sock.recvfrom(65535)
                        if data:
                            self._handle_udp_packet(data, addr)
                    except socket.timeout:
                        pass
                    except Exception as e:
                        logger.debug(f"UDP recv error: {e}")
                
                # Check TCP for async responses
                if self._tcp_sock:
                    try:
                        self._tcp_sock.settimeout(0.1)
                        resp_header = self._tcp_sock.recv(4, socket.MSG_PEEK)
                        if resp_header and len(resp_header) == 4:
                            resp_len = struct.unpack(">I", resp_header)[0]
                            resp_data = self._recv_exact(4 + resp_len)
                            if resp_data:
                                resp = json.loads(resp_data[4:].decode("utf-8"))
                                self._handle_async_response(resp)
                    except socket.timeout:
                        pass
                    except Exception as e:
                        logger.debug(f"TCP async recv error: {e}")
                        
            except Exception as e:
                logger.error(f"Recv loop error: {e}")
                time.sleep(0.1)
    
    def _handle_udp_packet(self, data: bytes, addr: tuple):
        """Handle incoming UDP packet (video frame or control)."""
        if len(data) < 20:
            return
        
        # Check if it's a video frame (has frame header)
        try:
            header = FrameHeader.parse(data)
            if header.size > 0 and header.size <= len(data) - 20:
                frame_data = data[20:20 + header.size]
                
                # Decrypt if we have session key
                if self.session.session_key and len(self.session.session_key) == 16:
                    frame_data = self._decrypt_frame(frame_data, header)
                
                # Queue frame
                try:
                    self._frame_queue.put_nowait({
                        "header": header,
                        "data": frame_data,
                        "timestamp": time.time()
                    })
                except Exception:
                    pass  # Queue full, drop frame
                    
        except Exception as e:
            logger.debug(f"Frame parse error: {e}")
    
    def _decrypt_frame(self, data: bytes, header: FrameHeader) -> bytes:
        """Decrypt frame using iotc_ms_frame_cipher equivalent (AES-CBC)."""
        # Based on analysis: media_data_decrypt / iotc_ms_frame_cipher
        # Uses AES-128-CBC with session_key and session_iv
        try:
            from Crypto.Cipher import AES
            cipher = AES.new(self.session.session_key, AES.MODE_CBC, self.session.session_iv)
            # PKCS7 unpadding
            decrypted = cipher.decrypt(data)
            pad_len = decrypted[-1]
            if 1 <= pad_len <= 16:
                return decrypted[:-pad_len]
            return decrypted
        except Exception:
            return data  # Return undecrypted if crypto fails
    
    def _handle_async_response(self, resp: dict):
        """Handle async TCP response (key exchange refresh, etc.)."""
        cmd = resp.get("cmd")
        if cmd == CommandCode.KEY_EXCHANGE:
            # Refresh session keys
            data = resp.get("data", {})
            self.session.session_key = base64.b64decode(data.get("skey", ""))
            self.session.session_iv = base64.b64decode(data.get("iv", ""))
            self.session.token = data.get("token", self.session.token)
            self.session.token_expiry = time.time() + data.get("expires_in", 3600)
        elif cmd == CommandCode.HEARTBEAT:
            self.session.last_heartbeat = time.time()
    
    def _heartbeat_loop(self):
        """Send periodic heartbeats and refresh tokens."""
        while self._running:
            time.sleep(30)  # Every 30 seconds
            if not self._running:
                break
            
            try:
                # Send heartbeat
                hb = {"cmd": CommandCode.HEARTBEAT, "seq": self._next_seq()}
                if self.session.token:
                    hb["auth"] = {"token": self.session.token, "sid": self.session.session_id}
                self._send_tcp_command(hb, timeout=2.0)
                
                # Check if token needs refresh
                if time.time() > self.session.token_expiry - 60:
                    self._refresh_token()
                    
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
    
    def _refresh_token(self):
        """Refresh session token (refreshIpPortHandleToken / refreshMqKeyExchangeInfo)."""
        try:
            cmd = {
                "cmd": CommandCode.REFRESH_TOKEN,
                "seq": self._next_seq(),
                "auth": {"token": self.session.token, "sid": self.session.session_id}
            }
            resp = self._send_tcp_command(cmd)
            if resp and resp.get("ret") == 0:
                data = resp.get("data", {})
                self.session.token = data.get("token", self.session.token)
                self.session.token_expiry = time.time() + data.get("expires_in", 3600)
                logger.info("Token refreshed")
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
    
    # ==================== Public API ====================
    
    def get_frame(self, timeout: float = 5.0) -> Optional[Dict]:
        """Get next video frame (blocking)."""
        try:
            return self._frame_queue.get(timeout=timeout)
        except Empty:
            return None
    
    def get_latest_frame(self) -> Optional[Dict]:
        """Get latest frame (non-blocking, drops older frames)."""
        frames = []
        try:
            while True:
                frames.append(self._frame_queue.get_nowait())
        except Empty:
            pass
        return frames[-1] if frames else None
    
    def snapshot(self) -> Optional[bytes]:
        """Capture a single snapshot (GET_SNAPSHOT command)."""
        cmd = {"cmd": CommandCode.GET_SNAPSHOT, "seq": self._next_seq()}
        if self.session.token:
            cmd["auth"] = {"token": self.session.token, "sid": self.session.session_id}
        
        resp = self._send_tcp_command(cmd)
        if resp and resp.get("ret") == 0:
            data = resp.get("data", {})
            return base64.b64decode(data.get("image", ""))
        return None
    
    def send_ptz(self, action: str, pan: int = 0, tilt: int = 0, zoom: int = 0, 
                 speed: int = 5, preset: int = 0) -> bool:
        """
        Send PTZ command.
        action: move, stop, preset, zoom, focus, iris
        """
        cmd = {
            "cmd": CommandCode.PTZ_PARAM,
            "seq": self._next_seq(),
            "params": {
                "action": action,
                "pan": max(-100, min(100, pan)),
                "tilt": max(-100, min(100, tilt)),
                "zoom": max(0, min(100, zoom)),
                "speed": max(1, min(10, speed)),
                "preset": preset
            }
        }
        if self.session.token:
            cmd["auth"] = {"token": self.session.token, "sid": self.session.session_id}
        
        resp = self._send_tcp_command(cmd)
        return resp is not None and resp.get("ret") == 0
    
    def send_ptz_preset(self, action: str, preset_id: int, name: str = "") -> bool:
        """PTZ preset management (set, goto, delete)."""
        cmd = {
            "cmd": CommandCode.PTZ_PRESET,
            "seq": self._next_seq(),
            "params": {
                "action": action,  # set, goto, delete
                "preset_id": preset_id,
                "name": name
            }
        }
        if self.session.token:
            cmd["auth"] = {"token": self.session.token, "sid": self.session.session_id}
        
        resp = self._send_tcp_command(cmd)
        return resp is not None and resp.get("ret") == 0
    
    def start_stream(self) -> bool:
        """Start video stream (START_PLAY)."""
        cmd = {"cmd": CommandCode.START_PLAY, "seq": self._next_seq()}
        if self.session.token:
            cmd["auth"] = {"token": self.session.token, "sid": self.session.session_id}
        
        resp = self._send_tcp_command(cmd)
        return resp is not None and resp.get("ret") == 0
    
    def stop_stream(self) -> bool:
        """Stop video stream (STOP_PLAY)."""
        cmd = {"cmd": CommandCode.STOP_PLAY, "seq": self._next_seq()}
        if self.session.token:
            cmd["auth"] = {"token": self.session.token, "sid": self.session.session_id}
        
        resp = self._send_tcp_command(cmd)
        return resp is not None and resp.get("ret") == 0
    
    def check_connection(self) -> Dict[str, Any]:
        """Check connection status."""
        return {
            "connected": self._running and self._tcp_sock is not None,
            "session": {
                "handle": self.session.handle,
                "device_id": self.session.device_id,
                "sid": self.session.session_id,
                "has_token": bool(self.session.token),
                "token_expires_in": max(0, self.session.token_expiry - time.time()),
                "p2p_mode": self.session.p2p_mode
            },
            "queue_size": self._frame_queue.qsize(),
            "last_heartbeat": self.session.last_heartbeat
        }
    
    def disconnect(self):
        """Disconnect from camera."""
        self._running = False
        
        if self._recv_thread:
            self._recv_thread.join(timeout=2)
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=2)
        
        if self._tcp_sock:
            try:
                self._tcp_sock.close()
            except:
                pass
            self._tcp_sock = None
        
        if self._udp_sock:
            try:
                self._udp_sock.close()
            except:
                pass
            self._udp_sock = None
        
        logger.info("Disconnected from camera")
