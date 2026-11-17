#!/usr/bin/env python3
"""
Test client for V380 Camera MCP Server.
Run this to test the protocol implementation directly.
"""
import os
import sys
import time
import logging

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp_server.protocol import V380ProtocolClient, CameraConfig

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def test_connection():
    """Test basic connection and frame retrieval."""
    config = CameraConfig(
        ip=os.getenv("CAMERA_IP", "192.168.1.169"),
        port=int(os.getenv("CAMERA_PORT", "5050")),
        uid=os.getenv("CAMERA_ID", ""),
        username=os.getenv("CAMERA_USER", "admin"),
        password=os.getenv("CAMERA_PASS", ""),
    )
    
    logger.info(f"Connecting to {config.ip}:{config.port}...")
    client = V380ProtocolClient(config)
    
    if not client.connect(timeout=10):
        logger.error("Failed to connect")
        return False
    
    logger.info("Connected! Checking status...")
    status = client.check_connection()
    logger.info(f"Status: {status}")
    
    # Start stream
    logger.info("Starting stream...")
    if client.start_stream():
        logger.info("Stream started")
    else:
        logger.warning("Failed to start stream (may already be running)")
    
    # Get a few frames
    logger.info("Getting frames...")
    for i in range(5):
        frame = client.get_frame(timeout=3.0)
        if frame:
            header = frame["header"]
            logger.info(f"Frame {i+1}: type={header.frame_type}, "
                       f"key={header.is_key_frame()}, size={len(frame['data'])}, "
                       f"ts={frame['timestamp']:.3f}")
        else:
            logger.warning(f"Frame {i+1}: timeout")
    
    # Test PTZ
    logger.info("Testing PTZ...")
    client.send_ptz("move", pan=10, tilt=-5, speed=3)
    time.sleep(1)
    client.send_ptz("stop")
    
    # Test snapshot
    logger.info("Taking snapshot...")
    snap = client.snapshot()
    if snap:
        logger.info(f"Snapshot captured: {len(snap)} bytes")
    else:
        logger.warning("Snapshot failed")
    
    # Check status
    status = client.check_connection()
    logger.info(f"Final status: {status}")
    
    client.disconnect()
    logger.info("Disconnected")
    return True


if __name__ == "__main__":
    test_connection()
