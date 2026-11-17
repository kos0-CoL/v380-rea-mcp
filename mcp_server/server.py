"""
V380 Camera MCP Server
FastMCP-based server exposing camera control tools.
"""
import os
import logging
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP, Context

from .protocol import V380ProtocolClient, CameraConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("v380-mcp")

# Global camera client
_camera_client: Optional[V380ProtocolClient] = None


def get_camera_client() -> V380ProtocolClient:
    """Get or create the global camera client."""
    global _camera_client
    if _camera_client is None:
        config = CameraConfig(
            ip=os.getenv("CAMERA_IP", "192.168.1.169"),
            port=int(os.getenv("CAMERA_PORT", "5050")),
            uid=os.getenv("CAMERA_ID", ""),
            username=os.getenv("CAMERA_USER", "admin"),
            password=os.getenv("CAMERA_PASS", ""),
            use_ssl=os.getenv("CAMERA_SSL", "false").lower() == "true"
        )
        _camera_client = V380ProtocolClient(config)
        if not _camera_client.connect():
            raise RuntimeError(f"Failed to connect to camera at {config.ip}:{config.port}")
        logger.info("Camera connected successfully")
    return _camera_client


@asynccontextmanager
async def lifespan(app: FastMCP):
    """Application lifespan - connect on startup, disconnect on shutdown."""
    global _camera_client
    # Startup
    try:
        get_camera_client()
    except Exception as e:
        logger.error(f"Failed to connect to camera on startup: {e}")
    yield
    # Shutdown
    if _camera_client:
        _camera_client.disconnect()
        _camera_client = None


# Create FastMCP server
mcp = FastMCP("V380 Camera", lifespan=lifespan)


@mcp.tool()
def check_connection() -> Dict[str, Any]:
    """
    Check camera connection status and session health.
    
    Returns:
        Dict with connection status, session info, and queue size.
    """
    client = get_camera_client()
    return client.check_connection()


@mcp.tool()
def get_frame(timeout: float = 5.0, as_base64: bool = True) -> Dict[str, Any]:
    """
    Get a video frame from the camera.
    
    Args:
        timeout: Maximum time to wait for a frame (seconds)
        as_base64: If True, return frame as base64 string; else return raw bytes info
    
    Returns:
        Dict with frame data (base64 or info), header metadata, and timestamp.
    """
    client = get_camera_client()
    frame = client.get_frame(timeout=timeout)
    
    if frame is None:
        return {"error": "No frame received within timeout", "timeout": timeout}
    
    header = frame["header"]
    data = frame["data"]
    
    result = {
        "frame_type": header.frame_type,
        "is_key_frame": header.is_key_frame(),
        "size": len(data),
        "timestamp": frame["timestamp"],
        "flags": {"f1": header.flags1, "f2": header.flags2},
        "ts": (header.ts_high << 32) | header.ts_low
    }
    
    if as_base64:
        import base64
        result["data_base64"] = base64.b64encode(data).decode("ascii")
    else:
        result["data_info"] = f"{len(data)} bytes (use as_base64=true to get data)"
    
    return result


@mcp.tool()
def get_latest_frame(as_base64: bool = True) -> Dict[str, Any]:
    """
    Get the most recent video frame (non-blocking, drops older frames).
    
    Args:
        as_base64: If True, return frame as base64 string
    
    Returns:
        Dict with frame data and metadata, or error if no frame available.
    """
    client = get_camera_client()
    frame = client.get_latest_frame()
    
    if frame is None:
        return {"error": "No frame available"}
    
    header = frame["header"]
    data = frame["data"]
    
    result = {
        "frame_type": header.frame_type,
        "is_key_frame": header.is_key_frame(),
        "size": len(data),
        "timestamp": frame["timestamp"],
        "flags": {"f1": header.flags1, "f2": header.flags2},
        "ts": (header.ts_high << 32) | header.ts_low
    }
    
    if as_base64:
        import base64
        result["data_base64"] = base64.b64encode(data).decode("ascii")
    
    return result


@mcp.tool()
def snapshot(as_base64: bool = True) -> Dict[str, Any]:
    """
    Capture a single snapshot/image from the camera.
    
    Args:
        as_base64: If True, return image as base64 string
    
    Returns:
        Dict with image data or error.
    """
    client = get_camera_client()
    img_data = client.snapshot()
    
    if img_data is None:
        return {"error": "Failed to capture snapshot"}
    
    if as_base64:
        import base64
        return {
            "image_base64": base64.b64encode(img_data).decode("ascii"),
            "size": len(img_data)
        }
    else:
        return {"size": len(img_data), "info": "Use as_base64=true to get image data"}


@mcp.tool()
def send_ptz(
    action: str,
    pan: int = 0,
    tilt: int = 0,
    zoom: int = 0,
    speed: int = 5,
    preset: int = 0
) -> Dict[str, Any]:
    """
    Send PTZ (Pan/Tilt/Zoom) command to camera.
    
    Args:
        action: One of "move", "stop", "preset", "zoom", "focus", "iris"
        pan: Pan position (-100 to 100), positive = right
        tilt: Tilt position (-100 to 100), positive = up
        zoom: Zoom level (0 to 100)
        speed: Movement speed (1 to 10)
        preset: Preset ID for preset actions
    
    Returns:
        Dict with success status.
    """
    client = get_camera_client()
    
    valid_actions = ["move", "stop", "preset", "zoom", "focus", "iris"]
    if action not in valid_actions:
        return {"error": f"Invalid action '{action}'. Valid: {valid_actions}"}
    
    success = client.send_ptz(
        action=action,
        pan=max(-100, min(100, pan)),
        tilt=max(-100, min(100, tilt)),
        zoom=max(0, min(100, zoom)),
        speed=max(1, min(10, speed)),
        preset=preset
    )
    
    return {"success": success, "action": action, "params": {
        "pan": pan, "tilt": tilt, "zoom": zoom, "speed": speed, "preset": preset
    }}


@mcp.tool()
def ptz_preset(action: str, preset_id: int, name: str = "") -> Dict[str, Any]:
    """
    Manage PTZ presets.
    
    Args:
        action: "set" (save current position), "goto" (move to preset), "delete"
        preset_id: Preset number (1-255)
        name: Optional name for preset (when setting)
    
    Returns:
        Dict with success status.
    """
    client = get_camera_client()
    
    valid_actions = ["set", "goto", "delete"]
    if action not in valid_actions:
        return {"error": f"Invalid action '{action}'. Valid: {valid_actions}"}
    
    if not 1 <= preset_id <= 255:
        return {"error": "preset_id must be 1-255"}
    
    success = client.send_ptz_preset(action=action, preset_id=preset_id, name=name)
    return {"success": success, "action": action, "preset_id": preset_id, "name": name}


@mcp.tool()
def start_stream() -> Dict[str, Any]:
    """Start video streaming from camera."""
    client = get_camera_client()
    success = client.start_stream()
    return {"success": success, "message": "Stream started" if success else "Failed to start stream"}


@mcp.tool()
def stop_stream() -> Dict[str, Any]:
    """Stop video streaming from camera."""
    client = get_camera_client()
    success = client.stop_stream()
    return {"success": success, "message": "Stream stopped" if success else "Failed to stop stream"}


@mcp.tool()
def refresh_session() -> Dict[str, Any]:
    """Manually trigger session token refresh."""
    client = get_camera_client()
    # Access internal method
    try:
        client._refresh_token()
        return {"success": True, "message": "Token refreshed"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.resource("camera://status")
def camera_status() -> str:
    """Camera status as a resource."""
    import json
    client = get_camera_client()
    status = client.check_connection()
    return json.dumps(status, indent=2)


@mcp.resource("camera://config")
def camera_config() -> str:
    """Camera configuration (sanitized)."""
    import json
    config = CameraConfig()
    return json.dumps({
        "ip": config.ip,
        "port": config.port,
        "uid": config.uid,
        "username": config.username,
        "has_password": bool(config.password),
        "use_ssl": config.use_ssl
    }, indent=2)


if __name__ == "__main__":
    mcp.run()
