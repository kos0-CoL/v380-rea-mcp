# V380 Camera Protocol Analysis for MCP Server

Reverse engineering analysis of the V380 Pro camera app (com.macrovideo.v380pro) native libraries to implement a custom MCP server for camera control.

## Overview

This repository documents the communication protocol between the V380 Pro Android app and its cameras, extracted via:
- **JADX decompilation** of `com.macrovideo.v380pro.apk`
- **Ghidra analysis** of native `.so` libraries (armeabi-v7a)

## Key Findings

### Primary Library
**`libhsMediaLibrary.so`** (551 KB) - Main native library handling all camera network communication, loaded by `HSMediaLibrary.java`

### Transport Protocol
- **UDP only** (not TCP) - all communication via `sendto`/`recvfrom`
- Default port: **5050** (from `LoginHandle.java`)
- Default domain: **123.nvdvr.net**
- IPv4/IPv6 dual-stack support

### Command Codes

| Code | Name | Purpose |
|------|------|---------|
| `0x30200` | SPEAK_AUDIO | Send audio to server |
| `0x3030a` | KEEP_ALIVE | Heartbeat (~4 sec interval) |
| `0x30300` | GENERAL_CTRL | General control commands |
| `0x30308` | PTZ_ACTION | PTZ/movement control |
| `0x30202` | PTZ_PRESET | Preset/camera configuration |
| `0x30222` | PLAYBACK_CTRL | TFV3 playback control |
| `0x60200` | PTZ_ZOOM | Zoom control |
| `0x60201` | PTZ_FOCUS | Focus control |
| `0x60203` | PTZ_IRIS | Iris control |
| `0x60204` | PTZ_OTHER | Other PTZ commands |

### Packet Structure

#### Command Packet (JSON over UDP)
```json
{
  "seq": <sequence_number>,
  "cmd": <command_code>,
  "params": { ... },
  "auth": { "token": <session_token>, "sid": <session_id> }
}
```

Built via `initIotcReq()` → `createActionJsonObj()` → sent via `sendto()`

#### Video Frame Buffer (20-byte header)
```c
struct FrameHeader {
    uint32_t buffer_offset;     // +0x10
    uint32_t data_size;         // +0x14
    uint8_t  frame_type;        // +0x18
    uint8_t  flag1;             // +0x19
    uint8_t  flag2;             // +0x1a
    uint32_t timestamp;         // +0x1c
    uint32_t sequence;          // +0x20
};
```

### Frame Types
| Type | Values | Description |
|------|--------|-------------|
| Key Frame | 0, 2, 9, 36, 40, 50, 52 | I-frames |
| Video Frame | >22, ≠24,25,26 | Regular frames |
| Audio/Other | 26, 24, 25 | Non-video |

### Session Management
Key JNI functions in `libhsMediaLibrary.so`:
- `refreshIpPortHandleToken` - refresh IP/port/token
- `refreshSession(sid, skey)` - refresh session with key
- `refreshMqKeyExchangeInfo` - MQTT key exchange
- `refreshIpPortHandleTokenSession/Uuid` - variants
- `updateLoginHandle(handle, token_session)` - update login

### Frame Encryption (iotc cipher)
```c
struct _media_stream_frame_trans_info {
    uint8_t  cipher_mode;      // 1=encrypt, 2=decrypt
    uint8_t  frame_type;
    uint8_t  key[16];          // AES key
    uint8_t  iv[16];           // AES IV
    // ... frame data (312 bytes total)
};
```
Functions:
- `iotc_ms_frame_cipher_init(info, mode, type, key, iv)`
- `iotc_ms_frame_cipher(info, type)`
- `iotc_ms_frame_cipher_end(info)`

### PTZ Control (11 parameters)
```c
setPTZParam(handle, cmd, bool1, param1, bool2, param2, bool3, bool4, bool5, bool6, param3)
```

### Login Handle Structure
```java
mlHandle: long           // native session handle
mnDeviceID: int          // device ID
mnPort: int = 5050       // default port
mstrDomain: "123.nvdvr.net"
mbInLan: boolean         // LAN mode
mstrIP/mstrLanIP: String // camera IPs
sid: int                 // session ID
sKey: byte[]             // session key (16 bytes)
pKeyByte: byte[]         // public key
```

## MCP Server Implementation Checklist

1. **UDP Server** on port 5050 (IPv4/IPv6 dual-stack)
2. **Session Manager** - track `sid`, `sKey`, token refresh
3. **Command Router** - dispatch by command code
4. **JSON Parser** - parse `initIotcReq` format commands
5. **Frame Decryptor** - implement `iotc_ms_frame_cipher` (AES-based)
6. **PTZ Handler** - map command codes to camera controls
7. **Video Buffer** - circular buffer with 20-byte headers
8. **Keep-Alive** - respond to `0x3030a` every 4 seconds
9. **Login Flow** - implement token/session refresh

## Libraries Analyzed

| Library | Size | Purpose |
|---------|------|---------|
| `libhsMediaLibrary.so` | 551 KB | Main protocol, streaming, PTZ, crypto |
| `libhsUtils.so` | 266 KB | Socket init, frame buffers, queue mgmt |
| `libjutils.so` | 1 MB | JNI utilities, basic socket ops |
| `libnms.so` | 127 KB | Network management, string obfuscation |
| `libsys_misc.so` | 790 KB | System utilities, crypto (mbedtls) |

## Analysis Tools
- JADX (APK decompilation)
- Ghidra 12.2 (native library analysis)
- Architecture: ARM 32-bit (armeabi-v7a)

---

*Generated from REA analysis of V380 Pro v380 APK and native libraries*
