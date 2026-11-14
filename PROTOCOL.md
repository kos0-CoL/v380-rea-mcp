# V380 Camera Protocol Specification

## 1. Network Layer

### 1.1 Socket Creation
```c
// From libhsUtils.so:socket_init()
socket(AF_INET, SOCK_DGRAM, 0)      // IPv4
socket(AF_INET6, SOCK_DGRAM, 0)     // IPv6

// Port binding: automatic via OS
// Default remote port: 5050
```

### 1.2 Address Resolution
- `socket_init_by_host()` - resolves hostname via `gethostbyname()`
- `socket_init_ex()` - explicit IP with IPv4/IPv6 auto-detection
- Supports both IPv4 (family=2) and IPv6 (family=10)

## 2. Command Protocol

### 2.1 Request Format
All commands sent as JSON via UDP `sendto()`:

```json
{
  "ver": "1.0",
  "seq": 12345,
  "cmd": 0x30308,
  "t": 1700000000,
  "params": {
    "action": "ptz_move",
    "pan": 10,
    "tilt": -5,
    "zoom": 0
  },
  "auth": {
    "sid": 1001,
    "skey": "base64_encoded_16_byte_key",
    "token": "session_token_string"
  }
}
```

### 2.2 Response Format
```json
{
  "seq": 12345,
  "ret": 0,
  "cmd": 0x30308,
  "data": { ... },
  "token": "new_session_token"
}
```

### 2.3 Command Codes Detail

#### 0x30200 - SPEAK_AUDIO
Send audio data to camera for two-way talk
- Params: `audio_data` (base64), `format`, `sample_rate`

#### 0x3030a - KEEP_ALIVE
Heartbeat sent every ~4 seconds
- Params: `status`: "alive"
- Expected response: `{"ret": 0, "token": "refreshed_token"}`

#### 0x30308 - PTZ_ACTION
PTZ control with action types:
```json
{
  "action": "move|stop|preset|zoom|focus|iris",
  "pan": -100..100,
  "tilt": -100..100,
  "zoom": 0..100,
  "speed": 1..10,
  "preset_id": 1..255
}
```

#### 0x30202 - PTZ_PRESET
Preset management:
```json
{
  "action": "set|goto|delete",
  "preset_id": 1..255,
  "name": "Preset Name"
}
```

#### 0x60200/1/3/4 - PTZ Fine Control
- 0x60200: Zoom (param: zoom_level 0-100)
- 0x60201: Focus (param: focus_level 0-100, auto: bool)
- 0x60203: Iris (param: iris_level 0-100)
- 0x60204: Aux (param: action_id)

## 3. Session Management

### 3.1 Login Flow
1. App sends login request to camera (or MQTT broker)
2. Camera returns `LoginHandle` with:
   - `mlHandle`: native session pointer
   - `sid`: session ID (int)
   - `sKey`: 16-byte session key
   - `mnDeviceID`: device identifier
   - `mnPort`: camera port (usually 5050)

### 3.2 Token Refresh
Periodic calls to:
- `refreshIpPortHandleToken(device_id, channel, ip, port, token)`
- `refreshSession(sid, channel, skey)`
- `refreshMqKeyExchangeInfo(device_id, channel, mq_key, skey, iv)`

### 3.3 Key Exchange
MQTT-based key exchange for encrypted streams:
- `refreshMqKeyExchangeInfo` exchanges AES keys
- Keys used for `iotc_ms_frame_cipher` video encryption

## 4. Video Streaming

### 4.1 Stream Setup
1. `startPlay(handle)` - begins video stream
2. Camera sends video frames via UDP to client port
3. Frames encrypted with session keys

### 4.2 Frame Format
Each UDP packet contains one or more frames:

```
[Frame Header: 20 bytes][Frame Data: variable]
```

**Frame Header (from libhsUtils.so FIFO queue):**
```c
struct FrameHeader {
    uint32_t offset;      // +0x10: offset in circular buffer
    uint32_t size;        // +0x14: frame data size
    uint8_t  type;        // +0x18: frame type
    uint8_t  flags1;      // +0x19: key frame flag, etc.
    uint8_t  flags2;      // +0x1a: timestamp sync, etc.
    uint32_t ts_low;      // +0x1c: timestamp low 32 bits
    uint32_t ts_high;     // +0x20: timestamp high/sequence
};
```

### 4.3 Frame Types
```c
// From isFrameType(), isDataKeyFrame(), isVideoFrame()
#define FRAME_KEY_I       0   // I-frame
#define FRAME_KEY_P       2   // P-frame  
#define FRAME_KEY_IDR     9   // IDR frame
#define FRAME_SPS_PPS     0x24 // 36: SPS/PPS
#define FRAME_SEI         0x28 // 40: SEI
#define FRAME_AUD         0x32 // 50: AUD
#define FRAME_FILLER      0x34 // 52: Filler
```

### 4.4 Frame Decryption
```c
// From libhsMediaLibrary.so
struct _media_stream_frame_trans_info {
    uint8_t cipher_mode;     // 1=decrypt, 2=encrypt
    uint8_t frame_type;
    uint8_t key[16];         // AES-128 key from key exchange
    uint8_t iv[16];          // IV from key exchange
    // ... 280 more bytes
};

// Usage:
iotc_ms_frame_cipher_init(&info, 1, frame_type, key, iv);
iotc_ms_frame_cipher(&info, frame_type);  // decrypts in-place
iotc_ms_frame_cipher_end(&info);
```

## 5. Audio Streaming

### 5.1 Audio Format
- Codec: ADPCM (from `AdpcmEncode`/`AdpcmDecode`)
- Sample rate: 8kHz (from `sample8kTo16k`)
- Channels: 1 (mono)

### 5.2 Commands
- `sendSpeakAudioData(handle, data, len, ...)` - send audio to camera
- `startSpeak(handle)` / `stopSpeak(handle)` - control two-way audio

## 6. Data Structures

### 6.1 LoginHandle (Java → Native)
```java
public class LoginHandle {
    long mlHandle;           // native handle
    int mnDeviceID;          // device ID
    long mlTokenSession;     // token session
    int sid;                 // session ID
    byte[] sKey;             // 16-byte session key
    byte[] pKeyByte;         // public key
    String mstrIP;           // camera IP
    String mstrLanIP;        // LAN IP
    int mnPort;              // port (default 5050)
    String mstrDomain;       // "123.nvdvr.net"
    boolean mbInLan;         // LAN mode
    // ... 80+ more fields
}
```

### 6.2 FIFO Queue (libhsUtils.so)
```c
struct FIFOQueue {
    uint8_t  initialized;    // +0x0
    uint16_t write_idx;      // +0x2
    uint16_t read_idx;       // +0x4
    uint16_t capacity;       // +0x7e0 (default 100)
    uint32_t buf_size;       // +0x7e4
    uint32_t free_space;     // +0x7e8
    uint32_t write_pos;      // +0x7ec
    uint32_t read_pos;       // +0x7f0
    void*    buffer;         // +0x7f4
    FrameHeader frames[100]; // +0x14 each (0x14*100=0x7d0)
};
```

## 7. Error Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| -1 | Generic failure |
| -2 | Invalid parameter |
| -3 | Not connected |
| -4 | Timeout |
| -5 | Authentication failed |
| -6 | Session expired |
| -7 | Encryption error |
| -8 | Buffer full |
| -9 | Not supported |

## 8. Constants

```c
#define DEFAULT_PORT        5050
#define DEFAULT_DOMAIN      "123.nvdvr.net"
#define MAX_FRAME_SIZE      0x100000  // 1MB
#define FIFO_CAPACITY       100
#define FRAME_HEADER_SIZE   20
#define SESSION_KEY_SIZE    16
#define KEEP_ALIVE_INTERVAL 4000  // ms
#define SELECT_TIMEOUT      3500  // ms (3.5 sec)
```
