# Deep Filter (medium) writeup

## Challenge
We are given a PNG image (the “strangly compressed PNG”) and told it is the last uploaded file from a missing courier. The title “Deep Filter” is the main hint.

Flag format:
HACKDAY{flag}

## Key observation: PNG scanline filters exist
PNG images are stored as compressed scanlines. Each scanline begins with a single byte called the filter type:

- 0 = None
- 1 = Sub
- 2 = Up
- 3 = Average
- 4 = Paeth

This filter byte is not “pixel data”, but it is part of the compressed stream (IDAT). That makes it a perfect hiding channel: you can encode data by choosing filter types per row.

The challenge name “Deep Filter” suggests the hidden message is in these filter bytes rather than in visible pixels or LSBs.

## Step 1: Extract and inflate IDAT
PNG stores compressed image data across one or more IDAT chunks. Concatenate all IDAT chunk payloads, then zlib-decompress them to get the raw scanline stream.

That raw stream looks like:
[filter_byte][scanline_bytes][filter_byte][scanline_bytes]...

## Step 2: Read the filter byte of every row
For a truecolor (RGB) 8-bit PNG, each row has:
1 filter byte + (3 * width) bytes

So the filter byte for row y is the first byte of that row in the decompressed stream.

In this challenge, only filter values 1 and 2 appear. That is suspiciously binary.

## Step 3: Interpret filter types as bits
Map:
- filter 1 -> bit 0
- filter 2 -> bit 1

Read bits row-by-row from top to bottom.

Then group into bytes (8 bits at a time, MSB-first) and convert to ASCII.

That decoded ASCII string is the flag text.

## Python solver (extract filter bytes and decode)
```py
import struct, zlib

path = "logo.png"   # the provided PNG

data = open(path, "rb").read()
assert data[:8] == b"\x89PNG\r\n\x1a\n"

# Collect IDAT
off = 8
idat = b""
ihdr = None
while off < len(data):
    ln = struct.unpack(">I", data[off:off+4])[0]
    typ = data[off+4:off+8]
    chunk = data[off+8:off+8+ln]
    off += 12 + ln
    if typ == b"IHDR":
        ihdr = chunk
    elif typ == b"IDAT":
        idat += chunk
    elif typ == b"IEND":
        break

w, h = struct.unpack(">II", ihdr[:8])
bit_depth = ihdr[8]
color_type = ihdr[9]
assert bit_depth == 8 and color_type == 2  # RGB, 8-bit

raw = zlib.decompress(idat)

stride = 1 + 3*w  # filter byte + RGB bytes
filters = [raw[y*stride] for y in range(h)]

# The stego channel: filter type is either 1 or 2
bits = []
for f in filters:
    if f == 1:
        bits.append(0)
    elif f == 2:
        bits.append(1)
    else:
        # If you see other values, adjust mapping or check you have the original PNG
        pass

# Bits -> bytes (MSB-first)
out = bytearray()
for i in range(0, len(bits)//8*8, 8):
    b = 0
    for j in range(8):
        b = (b << 1) | bits[i+j]
    out.append(b)

print(out.rstrip(b"\x00").decode("ascii", errors="replace"))
```

## Output / flag
The decoded ASCII text is:

HACKDAY{S0_MuCh_D4T4_!N_PnG}

## Final flag
HACKDAY{S0_MuCh_D4T4_!N_PnG}
