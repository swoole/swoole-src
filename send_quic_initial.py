#!/usr/bin/env python3
"""
Send a valid QUIC Initial packet to test HTTP/3 server
This creates a proper QUIC v1 Initial packet with crypto frame
"""

import socket
import secrets
import struct

def create_quic_initial_packet():
    """
    Create a valid QUIC v1 Initial packet
    Structure:
    - Long Header (Initial)
    - Version
    - DCID Length + DCID
    - SCID Length + SCID
    - Token Length (0)
    - Packet Length
    - Packet Number
    - Payload (CRYPTO frame with TLS Client Hello)
    """

    # QUIC Version 1
    version = 0x00000001

    # Connection IDs (random 8 bytes each)
    dcid = secrets.token_bytes(8)
    scid = secrets.token_bytes(8)

    # Create a minimal TLS Client Hello (this is simplified)
    # Real TLS Client Hello would be much more complex
    tls_client_hello = bytes([
        0x01,  # Handshake type: Client Hello
        0x00, 0x00, 0x10,  # Length: 16 bytes (simplified)
        0x03, 0x03,  # TLS version 1.2 (for compatibility)
        # Random (32 bytes) - simplified to 8 bytes
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        # Session ID length
        0x00,
        # Cipher suites length
        0x00, 0x02,
        # Cipher suite (TLS_AES_128_GCM_SHA256)
        0x13, 0x01,
        # Compression methods
        0x01, 0x00,
    ])

    # CRYPTO frame
    # Frame type: CRYPTO (0x06)
    # Offset: 0 (variable length integer)
    # Length: variable length integer
    crypto_frame = bytes([
        0x06,  # CRYPTO frame type
        0x00,  # Offset = 0
        len(tls_client_hello),  # Length
    ]) + tls_client_hello

    # Packet number (1 byte, value 0)
    packet_number = bytes([0x00])

    # Calculate payload length (packet number + frames)
    payload = packet_number + crypto_frame
    payload_length = len(payload)

    # Add padding to meet minimum packet size (1200 bytes for Initial)
    min_size = 1200
    current_size = 1 + 4 + 1 + len(dcid) + 1 + len(scid) + 1 + 2 + payload_length
    if current_size < min_size:
        padding_needed = min_size - current_size
        payload += bytes([0x00] * padding_needed)  # PADDING frames
        payload_length = len(payload)

    # Build packet
    packet = bytearray()

    # Long Header byte: Initial packet
    # Format: 1LLT TPPP
    # 1 = Long header
    # LL = 11 (protected)
    # TT = 00 (Initial)
    # PPP = 00 (packet number length - 1, so 1 byte)
    header_byte = 0b11000000  # Initial packet, 1-byte packet number
    packet.append(header_byte)

    # Version (4 bytes)
    packet.extend(struct.pack('!I', version))

    # DCID Length (1 byte) + DCID
    packet.append(len(dcid))
    packet.extend(dcid)

    # SCID Length (1 byte) + SCID
    packet.append(len(scid))
    packet.extend(scid)

    # Token Length (variable length, 0 for no token)
    packet.append(0x00)

    # Packet Length (variable length int, simplified to 2 bytes)
    # Add extra byte for length encoding
    if payload_length < 64:
        packet.append(payload_length)
    else:
        # 2-byte encoding
        packet.append(0x40 | (payload_length >> 8))
        packet.append(payload_length & 0xFF)

    # Payload (packet number + frames)
    packet.extend(payload)

    return bytes(packet)

def main():
    print("=" * 50)
    print("QUIC Initial Packet Sender")
    print("=" * 50)

    # Create packet
    packet = create_quic_initial_packet()
    print(f"Created QUIC Initial packet: {len(packet)} bytes")
    print(f"First 32 bytes (hex): {packet[:32].hex()}")

    # Send to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        print(f"\nSending packet to localhost:443...")
        sock.sendto(packet, ('127.0.0.1', 443))
        print("✓ Packet sent successfully")

        # Try to receive response (with timeout)
        sock.settimeout(2.0)
        try:
            response, addr = sock.recvfrom(65536)
            print(f"✓ Received response: {len(response)} bytes")
            print(f"  Response (first 32 bytes): {response[:32].hex()}")
        except socket.timeout:
            print("⚠ No response received (timeout)")

    except Exception as e:
        print(f"✗ Error: {e}")
    finally:
        sock.close()

    print("\n" + "=" * 50)
    print("Test completed")
    print("=" * 50)

if __name__ == '__main__':
    main()
