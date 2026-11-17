# V380 Camera MCP Server

A Model Context Protocol (MCP) server for controlling V380/Aliothings cameras, built from reverse engineering analysis of the V380 Pro Android app native libraries.

## Background

This implementation is based on REA/Ghidra analysis of the native libraries from `com.macrovideo.v380pro.apk`:
- `libhsMediaLibrary.so` - Main media/streaming/PTZ library
- `libhsUtils.so` - Socket/network utilities
- `libnms.so` - Network management
- `libzerolink.so` - SmartLink WiFi provisioning

## Key Protocol Findings

| Aspect | Discovery |
|--------|-----------|
| **Transport** | TCP (control) + UDP (video) |
| **Discovery** | NOT `NVDEVSEARCH^100` - uses MQTT/P2P via `callbackMqErrorStartP2p` |
| **Session** | MQTT-based key exchange → `refreshIpPortHandleToken` / `refreshMqKeyExchangeInfo` |
| **Encryption** | AES-128-CBC via `iotc_ms_frame_cipher_*` / `media_data_decrypt` |
| **PTZ** | `setPTZParam` (11 params) / `setPTZXParam` (3 params) |
| **Video** | `startPlay` → frames via `callbackPreviewRes` with 20-byte header |

## Installation

```bash
pip install -r requirements.txt
# Or manually:
pip install fastmcp pycryptodome pydantic
```

## Configuration

Set environment variables:

```bash
export CAMERA_IP="192.168.1.169"      # Camera IP address
export CAMERA_PORT="5050"             # Camera port (default 5050)
export CAMERA_ID=""                   # Camera UID/Device ID (optional)
export CAMERA_USER="admin"            # Username
export CAMERA_PASS="your_password"    # Password
export CAMERA_SSL="false"             # Use SSL/TLS
```

## Running the MCP Server

```bash
# Run as MCP server (for Claude Desktop, etc.)
python -m mcp_server.server

# Or run test client directly
python test_client.py
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `check_connection` | Verify camera connection and session health |
| `get_frame` | Get a video frame (blocking, with timeout) |
| `get_latest_frame` | Get most recent frame (non-blocking) |
| `snapshot` | Capture a single JPEG snapshot |
| `send_ptz` | Pan/Tilt/Zoom control |
| `ptz_preset` | Manage PTZ presets (set/goto/delete) |
| `start_stream` / `stop_stream` | Control video streaming |
| `refresh_session` | Manually refresh session token |

## MCP Resources

| Resource | Description |
|----------|-------------|
| `camera://status` | Current connection status (JSON) |
| `camera://config` | Sanitized camera configuration |

## Usage with Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "v380-camera": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "/path/to/v380-rea-mcp",
      "env": {
        "CAMERA_IP": "192.168.1.169",
        "CAMERA_USER": "admin",
        "CAMERA_PASS": "your_password"
      }
    }
  }
}
```

## Protocol Details

### Frame Structure

Each video frame has a 20-byte header (from FIFO queue analysis):

```c
struct FrameHeader {
    uint32_t offset;      // +0x10: buffer offset
    uint32_t size;        // +0x14: frame data size
    uint8_t  frame_type;  // +0x18: 0=I, 2=P, 9=IDR, 36=SPS/PPS, etc.
    uint8_t  flags1;      // +0x19
    uint8_t  flags2;      // +0x1a
    uint32_t ts_low;      // +0x1c: timestamp low
    uint32_t ts_high;     // +0x20: timestamp high
};
```

### Encryption

Frames are encrypted with AES-128-CBC:
- Key: 16 bytes from MQTT key exchange (`sKey` in `LoginHandle`)
- IV: 16 bytes from key exchange
- Functions: `iotc_ms_frame_cipher_init` → `iotc_ms_frame_cipher` → `iotc_ms_frame_cipher_end`

### PTZ Commands

```python
# Move
send_ptz("move", pan=10, tilt=-5, zoom=0, speed=5)

# Preset management
ptz_preset("set", 1, "Front Door")
ptz_preset("goto", 1)
ptz_preset("delete", 1)
```

## Architecture

```
mcp_server/
├── __init__.py
├── protocol.py      # Low-level V380 protocol client
└── server.py        # FastMCP server with tools
```

## Requirements

- Python 3.10+
- `fastmcp>=2.0.0`
- `pycryptodome>=3.18.0` (AES decryption)
- `pydantic>=2.0.0`

## Testing

```bash
# Set camera credentials
export CAMERA_IP="192.168.1.169"
export CAMERA_PASS="your_password"

# Run test client
python test_client.py
```

## Notes

- The classic V380 discovery (`NVDEVSEARCH^100` on UDP 10008/10009) **does not work** for modern Aliothings-based cameras
- This implementation uses the MQTT/P2P path discovered in the native libraries
- Aggressive port scanning causes camera network stack to hang - avoid it
- The camera must be online and reachable via the V380 Pro app first
