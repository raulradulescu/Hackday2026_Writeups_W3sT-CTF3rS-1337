# CRT Start (100) -  writeup

## Files
- crt_start (ELF64, stripped)
- backup1999.bin (26 bytes)

## Quick recon
Running the binary with no arguments shows it expects one file:

    $ ./crt_start
    Usage: ./crt_start <backupfile>

Running it on the provided backup prints INVALID, which hints there is an additional hidden requirement besides the backup file contents.

A strings pass reveals an extra hardcoded filename:

    candidate.txt

So the program is not only parsing the backup, it also expects a local candidate.txt in the current working directory.

## Backup file format
Disassembling the main logic shows these checks:

- First 4 bytes must be the ASCII signature "HDR!".
- Next 4 bytes are a big-endian 32-bit value (call it seed0).
- Next 1 byte is a payload length (len).
- Next len bytes are the encrypted payload.

For the provided backup1999.bin:

- signature: "HDR!"
- seed0 bytes: 1f 35 b8 f4  -> 0x1f35b8f4
- len: 0x11 -> 17
- ciphertext (17 bytes): 46 a1 ae be d4 45 e9 71 41 20 1f 50 1b b1 2c f8 75

## Payload decryption (xorshift32 keystream)
The code transforms seed0 into an xorshift32 state:

1) seed0 = big_endian_u32(backup[4:8])
2) state = ror32(seed0, 5) XOR 0xa5a5a5a5

Then it decrypts each ciphertext byte using the top byte of the evolving xorshift32 state:

For each byte:
- state = xorshift32(state)
- keybyte = (state >> 24) & 0xff
- plaintext[i] = ciphertext[i] XOR keybyte

The xorshift32 used is the classic one:

    x ^= x << 13
    x ^= x >> 17
    x ^= x << 5

Applying this to backup1999.bin recovers:
```
    plaintext = b"HACKDAY1999BACKUP"
```
## What candidate.txt must contain
After decrypting, the binary opens candidate.txt, reads it as a line, trims trailing newline, and enforces:

- strlen(candidate_line) == 2 * len

So candidate.txt must be a hex string with exactly 2*len characters (34 chars here), representing len bytes.

It then parses candidate_line as hex pairs into candidate_bytes[len] and validates:

    candidate_bytes[i] == plaintext[i] XOR ((13*i + 7) & 0xff)

It also checks a checksum constraint:

    (sum(candidate_bytes) XOR state) & 0xffff == 0

With the provided backup, the checksum matches automatically when candidate_bytes is computed as above.

So the required candidate is deterministic:

    candidate_bytes = plaintext[i] XOR (13*i+7)
    candidate_hex   = candidate_bytes.hex()

For plaintext "HACKDAY1999BACKUP" (17 bytes), the resulting candidate hex is:
```
    4f5562657f090c535645b0d4e2f3f69f87
```
Create candidate.txt containing that line (newline at the end is fine).

## Final output / flag
With candidate.txt present, running the binary prints:

    HACKDAY{fdc880d28b983f51c4601e525cfad8fac9c5a6c0c18237467488ec44d3caedda}

This is the SHA-256 of the decrypted plaintext, printed as lowercase hex.

## Solver script (recreates candidate.txt and prints the flag)
```python
import hashlib
from pathlib import Path

def ror32(x, r):
    return ((x >> r) | ((x << (32 - r)) & 0xffffffff)) & 0xffffffff

def xorshift32(x):
    x &= 0xffffffff
    x ^= (x << 13) & 0xffffffff
    x ^= (x >> 17) & 0xffffffff
    x ^= (x << 5) & 0xffffffff
    return x & 0xffffffff

backup = Path("backup1999.bin").read_bytes()
assert backup[:4] == b"HDR!"

seed0 = int.from_bytes(backup[4:8], "big")
n = backup[8]
ct = backup[9:9+n]

state = ror32(seed0, 5) ^ 0xa5a5a5a5

pt = bytearray()
for b in ct:
    state = xorshift32(state)
    key = (state >> 24) & 0xff
    pt.append(b ^ key)

pt = bytes(pt)  # b"HACKDAY1999BACKUP"

cand = bytes([pt[i] ^ ((13*i + 7) & 0xff) for i in range(n)])
cand_hex = cand.hex()

# candidate.txt content
Path("candidate.txt").write_text(cand_hex + "\n")

# challenge flag is sha256(plaintext) in hex
flag_hash = hashlib.sha256(pt).hexdigest()
print(f"HACKDAY{{{flag_hash}}}")
```
Flag:
HACKDAY{fdc880d28b983f51c4601e525cfad8fac9c5a6c0c18237467488ec44d3caedda}
