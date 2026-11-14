"""
V380 Camera MCP Server Implementation
UDP-based server handling V380 camera protocol.
"""
import socket
import json
import threading
import time
import struct
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Optional, Callable, Any
from enum import IntEnum
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CommandCode(IntEnum):
    """V380 command codes from protocol analysis."""
    SPEAK_AUDIO = 0x30200
    KEEP_ALIVE = 0x3030a
    GENERAL_CTRL = 0x30300
    PTZ_ACTION = 0x30308
    PTZ_PRESET = 0x30202
    PLAYBACK_CTRL = 0x30222
    PTZ_ZOOM = 0x60200
    PTZ_FOCUS = 0x60201
    PTZ_IRIS = 0x60203
    PTZ_OTHER = 0x60204


class FrameType(IntEnum):
    """Video frame types."""
    I_FRAME = 0
    P_FRAME = 2
    IDR_FRAME = 9
    SPS_PPS = 36
    SEI = 40
    AUD = 50
    FILLER = 52


KEY_FRAME_TYPES = {0, 2, 9, 36, 40, 50, 52}


@dataclass
class Session:
    """Camera session state."""
    sid: int
    skey: bytes  # 16 bytes
    device_id: int
    handle: int
    ip: str
    port: int
    token: str = ""
    last_keepalive: float = 0
    expires_at: float = 0


@dataclass
class FrameHeader:
    """Video frame header (20 bytes)."""
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
        offset, size, ftype, f1, f2, ts_low, ts_high = struct.unpack(
            "<IIBBBII", data[:20]
        )
        return cls(offset, size, ftype, f1, f2, ts_low, ts_high)

    def is_key_frame(self) -> bool:
        return self.frame_type in KEY_FRAME_TYPES


class V380MCPServer:
    """Main MCP server for V380 cameras."""

    def __init__(self, host: str = "0.0.0.0", port: int = 5050):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.running = False
        self.sessions: Dict[str, Session] = {}  # key: f"{ip}:{port}"
        self.command_handlers: Dict[int, Callable] = {}
        self._register_handlers()

    def _register_handlers(self):
        """Register command handlers."""
        self.command_handlers = {
            CommandCode.KEEP_ALIVE: self._handle_keepalive,
            CommandCode.PTZ_ACTION: self._handle_ptz_action,
            CommandCode.PTZ_PRESET: self._handle_ptz_preset,
            CommandCode.PTZ_ZOOM: self._handle_ptz_zoom,
            CommandCode.PTZ_FOCUS: self._handle_ptz_focus,
            CommandCode.PTZ_IRIS: self._handle_ptz_iris,
            CommandCode.PTZ_OTHER: self._handle_ptz_other,
            CommandCode.GENERAL_CTRL: self._handle_general_ctrl,
            CommandCode.SPEAK_AUDIO: self._handle_speak_audio,
            CommandCode.PLAYBACK_CTRL: self._handle_playback_ctrl,
        }

    def start(self):
        """Start the UDP server."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.running = True

        logger.info(f"V380 MCP Server listening on {self.host}:{self.port}")

        # Start keepalive monitor thread
        threading.Thread(target=self._keepalive_monitor, daemon=True).start()

        # Main receive loop
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
                threading.Thread(
                    target=self._handle_packet, args=(data, addr), daemon=True
                ).start()
            except Exception as e:
                if self.running:
                    logger.error(f"Receive error: {e}")

    def stop(self):
        """Stop the server."""
        self.running = False
        if self.sock:
            self.sock.close()

    def _handle_packet(self, data: bytes, addr: tuple):
        """Process incoming UDP packet."""
        try:
            # Try to parse as JSON command
            text = data.decode("utf-8")
            msg = json.loads(text)
            self._handle_command(msg, addr)
        except (UnicodeDecodeError, json.JSONDecodeError):
            # Binary frame data
            self._handle_frame_data(data, addr)

    def _handle_command(self, msg: dict, addr: tuple):
        """Handle JSON command message."""
        cmd = msg.get("cmd", 0)
        seq = msg.get("seq", 0)
        auth = msg.get("auth", {})

        # Validate session
        sid = auth.get("sid")
        session = self._get_session(sid, addr) if sid else None

        handler = self.command_handlers.get(cmd)
        if handler:
            response = handler(msg, session, addr)
        else:
            response = {"ret": -9, "error": f"Unknown command: 0x{cmd:04x}"}

        response["seq"] = seq
        response["cmd"] = cmd
        self._send_response(response, addr)

    def _handle_frame_data(self, data: bytes, addr: tuple):
        """Handle incoming video frame data."""
        if len(data) < 20:
            return

        header = FrameHeader.parse(data)
        frame_data = data[20:20 + header.size]

        # Find session for this address
        session_key = f"{addr[0]}:{addr[1]}"
        session = self.sessions.get(session_key)

        if session and header.is_key_frame():
            # Decrypt frame if needed
            decrypted = self._decrypt_frame(frame_data, header, session)
            self._on_frame_received(decrypted, header, session)

    def _decrypt_frame(self, data: bytes, header: FrameHeader, session: Session) -> bytes:
        """Decrypt frame using iotc cipher (placeholder)."""
        # TODO: Implement AES-128-CBC decryption with session.skey
        # This would call iotc_ms_frame_cipher equivalent
        return data

    def _on_frame_received(self, data: bytes, header: FrameHeader, session: Session):
        """Callback for received frame - override in subclass."""
        logger.debug(f"Frame: type={header.frame_type}, size={len(data)}, key={header.is_key_frame()}")

    def _get_session(self, sid: int, addr: tuple) -> Optional[Session]:
        """Get or create session."""
        session_key = f"{addr[0]}:{addr[1]}"
        if session_key in self.sessions:
            session = self.sessions[session_key]
            if session.sid == sid:
                return session
        return None

    def _send_response(self, response: dict, addr: tuple):
        """Send JSON response."""
        data = json.dumps(response).encode("utf-8")
        if self.sock:
            self.sock.sendto(data, addr)

    # Command Handlers
    def _handle_keepalive(self, msg: dict, session: Optional[Session], addr: tuple) -> dict:
        if session:
            session.last_keepalive = time.time()
            # Refresh token
            new_token = hashlib.md5(f"{session.sid}{time.time()}".encode()).hexdigest()[:16]
            session.token = new_token
            return {"ret": 0, "token": new_token}
        return {"ret": -6, "error": "No session"}

    def _handle_ptz_action(self, msg: dict, session: Optional[Session], addr: tuple) -> dict:
        params = msg.get("params", {})
        action = params.get("action", "stop")
        logger.info(f"PTZ Action: {action}, pan={params.get('pan')}, tilt={params.get('tilt')}")
        return {"ret": 0, "action": action}

    def _handle_ptz_preset(self, msg: dict, session: Optional[Session], addr: tuple) -> dict:
        params = msg.get("params", {})
        action = params.get("action", "goto")
        preset_id = params.get("preset_id", 1)
        logger.info(f"PTZ Preset: {action} #{preset_id}")
        return {"ret": 0, "preset_id": preset_id}

    def _handle_ptz_zoom(self, msg: dict, session: Optional[Session], addr: tuple) -> dict:
        level = msg.get("params", {}).get("zoom_level", 0)
        logger.info(f"PTZ Zoom: {level}")
        return {"ret": 0, "zoom": level}

    def _handle_ptz_focus(self, msg: dict, session: Optional[Session], addr: tuple) -> dict:
        params = msg.get("params", {})
        level = params.get("focus_level", 0)
        auto = params.get("auto", True)
        logger.info(f"PTZ Focus: {level}, auto={auto}")
        return {"ret": 0, "focus": level}

    def _handle_ptz_iris(self, msg: dict, session: Optional[Session], addr: tuple) -> dict:
        level = msg.get("params", {}).get("iris_level", 0)
        logger.info(f"PTZ Iris: {level}")
        return {"ret": 0, "iris": level}

    def _handle_ptz_other(self, msg: dict, session: Optional[Session], addr: tuple) -> dict:
        action_id = msg.get("params", {}).get("action_id", 0)
        logger.info(f"PTZ Other: {action_id}")
        return {"ret": 0, "action_id": action_id}

    def _handle_general_ctrl(self, msg: dict, session: Optional[Session], addr: tuple) -> dict:
        params = msg.get("params", {})
        action = params.get("action", "")
        logger.info(f"General Ctrl: {action}")
        return {"ret": 0, "action": action}

    def _handle_speak_audio(self, msg: dict, session: Optional[Session], addr: tuple) -> dict:
        logger.info("Speak Audio received")
        return {"ret": 0}

    def _handle_playback_ctrl(self, msg: dict, session: Optional[Session], addr: tuple) -> dict:
        params = msg.get("params", {})
        action = params.get("action", "")
        logger.info(f"Playback Ctrl: {action}")
        return {"ret": 0, "action": action}

    def _keepalive_monitor(self):
        """Monitor session keepalives."""
        while self.running:
            time.sleep(5)
            now = time.time()
            expired = [
                k for k, s in self.sessions.items()
                if now - s.last_keepalive > 10  # 10 sec timeout
            ]
            for k in expired:
                logger.info(f"Session expired: {k}")
                del self.sessions[k]


def main():
    server = V380MCPServer()
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.stop()


if __name__ == "__main__":
    main()
