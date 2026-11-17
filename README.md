# V380 Camera MCP Server

A Model Context Protocol (MCP) server for controlling V380/Aliothings cameras, built from reverse engineering analysis of the V380 Pro Android app native libraries.

## Background

This implementation is based on REA/Ghidra analysis of the native libraries from `com.macrovideo.v380pro.apk`:
- `libhsMediaLibrary.so` - Main media/streaming/PTZ library (551 KB)
- `libhsUtils.so` - Socket/network utilities (266 KB)
- `libnms.so` - Network management (127 KB)
- `libzerolink.so` - SmartLink WiFi provisioning (9 KB)

## Key Protocol Findings

| Aspect | Discovery |
|--------|-----------|
| **Transport** | TCP (control, `mr_tcp_connect`) + UDP (video) |
| **Discovery** | NOT `NVDEVSEARCH^100` — uses MQTT/P2P via `callbackMqErrorStartP2p` |
| **Session** | MQTT-based key exchange → `refreshIpPortHandleToken` / `refreshMqKeyExchangeInfo` |
| **Encryption** | AES-128-CBC via `iotc_ms_frame_cipher_*` / `media_data_decrypt` |
| **Frame Header** | 20 bytes (offset, size, type, flags, timestamp) |
| **PTZ** | `setPTZParam` (11 params) / `setPTZXParam` (3 params) |
| **Video Types** | 1=Video, 2=Audio, 4=Other |
| **SmartLink** | WiFi provisioning via libzerolink.so (UDP broadcast) |

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
| `refresh_session` | Manual token refresh |

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
    uint8_t  frame_type;  // +0x18: 1=video, 2=audio, 4=other
    uint8_t  flags1;      // +0x19
    uint8_t  flags2;      // +0x1a
    uint32_t ts_low;      // +0x1c: timestamp low
    uint32_t ts_high;     // +0x20: timestamp high
};
```

### tagFrameData Structure

```c
struct tagFrameData {
    uint32_t frame_type;      // +0: 1=video, 2=audio, 4=other
    uint32_t timestamp;       // +4
    uint32_t sub_type;        // +8
    uint16_t frame_subtype;   // +0xc
    uint32_t pts_low;         // +0x10
    uint32_t pts_high;        // +0x14
    uint32_t width;           // +0x18
    uint32_t height;          // +0x1c
    uint32_t data_size;       // +0x20
    uint32_t data_offset;     // +0x24
    uint32_t flags;           // +0x28
    uint32_t sequence;        // +0x2c
    uint32_t stream_id;       // +0x30
    uint32_t extra_data;      // +0x44
};
```

### Encryption

Frames are encrypted with AES-128-CBC:
- Key: 16 bytes from MQTT key exchange (`sKey` in `LoginHandle`)
- IV: 16 bytes from key exchange
- Functions: `iotc_ms_frame_cipher_init` → `iotc_ms_frame_cipher` → `iotc_ms_frame_cipher_end`
- Frame info struct: `_media_stream_frame_trans_info` (312 bytes)

### PTZ Commands

```python
# Move
send_ptz("move", pan=10, tilt=-5, zoom=0, speed=5)

# Preset management
ptz_preset("set", 1, "Front Door")
ptz_preset("goto", 1)
ptz_preset("delete", 1)
```

### Key Exchange Flow

```
1. LoginHelper.login(context, deviceInfo, 5) → P2P login
2. Key exchange via:
   - LoginHelper.keyExchangeFromMqSync()     # MQTT
   - LoginHelper.keyExchangeByLanSync()      # LAN
   - LoginHelper.keyExchangeFromHttpsSync()  # HTTPS fallback
3. Session maintained via:
   - refreshIpPortHandleToken()
   - refreshMqKeyExchangeInfo()
   - refreshSession()
```

### Video Flow

```
startPlay() 
  → HSMediaManager::startPlay(tagPlayParam)
  → callbackPreviewReq() / callbackPreviewRes()
  → onRecvFrameData(tagFrameData*)
  → PutFileFrameDataTime3() (video) / PutAudioDataEX() (audio)
  → Frames queued in FIFO (100 capacity, 20-byte headers)
```

### Native Symbols (for further REA)

| Symbol | Address | Description |
|--------|---------|-------------|
| `Java_com_macrovideo_sdk_media_HSMediaLibrary_startPlay` | 0x89e08 | Start video stream |
| `Java_com_macrovideo_sdk_media_HSMediaLibrary_setPTZParam` | 0x8a7cc | PTZ control (11 params) |
| `Java_com_macrovideo_sdk_media_HSMediaLibrary_refreshIpPortHandleToken` | 0x907b8 | Token refresh |
| `Java_com_macrovideo_sdk_media_HSMediaLibrary_refreshMqKeyExchangeInfo` | 0x90adc | MQTT key exchange |
| `Java_com_macrovideo_sdk_media_HSMediaLibrary_cipherFileData` | 0x8f418 | Frame encryption |
| `mr_tcp_connect` | - | TCP connection for control |
| `iotc_ms_frame_cipher_init` | - | Init AES cipher |
| `iotc_ms_frame_cipher` | - | Encrypt/decrypt frame |

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
# Configure
export CAMERA_IP="192.168.1.169"
export CAMERA_PASS="***"

# Run test client
python test_client.py

# Or run MCP server
python -m mcp_server.server
```

## Notes

- The classic V380 discovery (`NVDEVSEARCH^100` on UDP 10008/10009) **does not work** for modern Aliothings-based cameras
- This implementation uses the MQTT/P2P path discovered in the native libraries
- Aggressive port scanning causes camera network stack to hang - avoid it
- The camera must be online and reachable via the V380 Pro app first
- SmartLink WiFi provisioning uses libzerolink.so with UDP broadcast to 228.84.85.%d
