"""Pure-python port of lzkn64 0.2.0 decompressor (Konami LZKN64 / Nisitenma-Ichigo)."""
import struct

SIG = b"Nisitenma-Ichigo"


def decompress_chunk(data, out):
    i = 0
    n = len(data)
    while i < n:
        c = data[i]
        i += 1
        if c <= 0x7F:                                  # sliding window copy
            if i >= n:
                break
            nb = data[i]; i += 1
            length = ((c & 0x7C) >> 2) + 2
            offset = (((c & 0x03) << 8) | nb) & 0x3FF
            if offset == 0 or offset > len(out):
                raise ValueError(f"bad backref offset {offset} at {i}")
            start = len(out) - offset
            for k in range(length):
                out.append(out[start + k])
        elif 0x80 <= c <= 0x9F:                        # raw copy
            length = c & 0x1F
            out += data[i:i + length]
            i += length
        elif 0xC0 <= c <= 0xDF:                        # RLE short, any value
            length = (c & 0x1F) + 2
            if i >= n:
                break
            v = data[i]; i += 1
            out += bytes([v]) * length
        elif 0xE0 <= c <= 0xFE:                        # RLE short, zero
            out += b"\0" * ((c & 0x1F) + 2)
        elif c == 0xFF:                                # RLE long, zero
            if i >= n:
                break
            ln = data[i]; i += 1
            out += b"\0" * (ln + 2)
        else:
            raise ValueError(f"unknown command byte {c:#04x}")
    return out


def decompress(buf):
    """Decompress a full LZKN64 stream (one or more chunks)."""
    out = bytearray()
    pos = 0
    while pos + 4 <= len(buf):
        hdr, = struct.unpack_from(">I", buf, pos)
        planes = ((hdr >> 28) & 0x0F) + 1
        size = hdr & 0x0FFFFFFF
        if planes > 1:
            raise ValueError(f"interleaved planes unsupported (planes={planes})")
        if size < 4:
            raise ValueError(f"bad chunk size {size:#x}")
        body = buf[pos + 4: pos + size]
        if len(body) < size - 4:
            raise ValueError("truncated chunk")
        pos += size
        if body:
            decompress_chunk(body, out)
    return bytes(out)


def file_table(rom):
    """Return (sig_offset, [(index, start, end, compressed), ...])."""
    sig = rom.find(SIG)
    if sig < 0:
        raise ValueError("Nisitenma-Ichigo signature not found")
    off = sig + len(SIG)
    raw = []
    while True:
        v, = struct.unpack_from(">I", rom, off + len(raw) * 4)
        if v == 0:
            break
        raw.append(v)
    files = []
    for n in range(len(raw) - 1):
        files.append((n, raw[n] & 0x7FFFFFFF, raw[n + 1] & 0x7FFFFFFF, bool(raw[n] >> 31)))
    return sig, files
