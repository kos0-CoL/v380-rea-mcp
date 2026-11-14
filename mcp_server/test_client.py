"""
Test client for V380 MCP Server.
Sends sample commands to test the protocol.
"""
import socket
import json
import time
import threading


class V380TestClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 5050):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(5.0)
        self.seq = 0
        self.sid = 1001
        self.token = ""

    def _next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def send_command(self, cmd: int, params: dict = None, auth: dict = None) -> dict:
        """Send command and wait for response."""
        if params is None:
            params = {}
        if auth is None:
            auth = {"sid": self.sid}
        if self.token:
            auth["token"] = self.token

        msg = {
            "ver": "1.0",
            "seq": self._next_seq(),
            "cmd": cmd,
            "t": int(time.time()),
            "params": params,
            "auth": auth
        }

        data = json.dumps(msg).encode("utf-8")
        self.sock.sendto(data, (self.host, self.port))

        try:
            resp_data, _ = self.sock.recvfrom(65535)
            return json.loads(resp_data.decode("utf-8"))
        except socket.timeout:
            return {"error": "timeout"}

    def keepalive(self):
        return self.send_command(0x3030a, {"status": "alive"})

    def ptz_move(self, pan: int = 0, tilt: int = 0, zoom: int = 0, speed: int = 5):
        return self.send_command(0x30308, {
            "action": "move",
            "pan": pan,
            "tilt": tilt,
            "zoom": zoom,
            "speed": speed
        })

    def ptz_stop(self):
        return self.send_command(0x30308, {"action": "stop"})

    def ptz_zoom(self, level: int):
        return self.send_command(0x60200, {"zoom_level": level})

    def ptz_focus(self, level: int, auto: bool = True):
        return self.send_command(0x60201, {"focus_level": level, "auto": auto})

    def ptz_preset_set(self, preset_id: int, name: str = ""):
        return self.send_command(0x30202, {
            "action": "set",
            "preset_id": preset_id,
            "name": name
        })

    def ptz_preset_goto(self, preset_id: int):
        return self.send_command(0x30202, {
            "action": "goto",
            "preset_id": preset_id
        })


def main():
    client = V380TestClient("127.0.0.1", 5050)

    print("Testing V380 MCP Server...")
    
    # Test keepalive
    print("\n1. Keepalive:")
    resp = client.keepalive()
    print(f"   Response: {resp}")
    if "token" in resp:
        client.token = resp["token"]
        print(f"   Got token: {client.token}")

    # Test PTZ move
    print("\n2. PTZ Move (pan=10, tilt=-5):")
    resp = client.ptz_move(pan=10, tilt=-5, speed=5)
    print(f"   Response: {resp}")

    # Test PTZ zoom
    print("\n3. PTZ Zoom (level=50):")
    resp = client.ptz_zoom(50)
    print(f"   Response: {resp}")

    # Test PTZ focus
    print("\n4. PTZ Focus (level=75, auto=False):")
    resp = client.ptz_focus(75, auto=False)
    print(f"   Response: {resp}")

    # Test preset
    print("\n5. PTZ Preset Set (#1, 'Front Door'):")
    resp = client.ptz_preset_set(1, "Front Door")
    print(f"   Response: {resp}")

    print("\n6. PTZ Preset Goto (#1):")
    resp = client.ptz_preset_goto(1)
    print(f"   Response: {resp}")

    # Test stop
    print("\n7. PTZ Stop:")
    resp = client.ptz_stop()
    print(f"   Response: {resp}")

    print("\nDone!")


if __name__ == "__main__":
    main()
