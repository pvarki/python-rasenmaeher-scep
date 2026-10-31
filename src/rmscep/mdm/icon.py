"""A launcher icon, generated rather than shipped

Google will not publish a managed web app without one, and a web app it has not published is
accepted by the MDM but reports NOT_FOUND on every device that tries to install it. Square and at
least 512x512 are enforced. Generating it avoids carrying a binary in the repository for something
no one will look at twice.
"""

import struct
import zlib


def launcher_icon(size: int = 512) -> bytes:
    """A plain square PNG, no dependencies"""

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    rows = []
    for y in range(size):
        pixels = bytearray()
        for x in range(size):
            inside = abs(x - size // 2) < size // 3 and size // 6 < y < size * 5 // 6
            pixels += bytes((0x0D, 0x47, 0xA1) if inside else (0x10, 0x1A, 0x24))
        rows.append(b"\x00" + bytes(pixels))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b"".join(rows), 9))
        + chunk(b"IEND", b"")
    )
