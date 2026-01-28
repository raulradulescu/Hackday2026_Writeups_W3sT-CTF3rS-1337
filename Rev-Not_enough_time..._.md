# not enough time...

## files
- Agent (ELF64, stripped)
- flag.txt (one encrypted sample)

## safety note
The binary walks a directory recursively and overwrites files in place. Do not run it on a real folder. If you must run it, do it in an isolated VM and point it at a throwaway directory.

## quick recon
Basic inspection shows the binary is a C++ program using:
- std::filesystem (recursive_directory_iterator)
- OpenSSL SHA-256 (SHA256_Init/Update/Final)
- libcurl (it even references the Mistral API endpoint)

The “Mistral API key” prompt is a distraction for solving the crypto; the actual file encryption uses a locally derived keystream.

## key derivation (from static analysis)
In the disassembly you can spot:
- a call to time()
- arithmetic that implements floor(time/60) using a “magic constant” multiply
- reconstruction of t60 = (time() // 60) * 60
- XOR with the constant 0xDEADC0DE
- conversion of that 32-bit value to a decimal ASCII string
- SHA-256 of that string
- conversion of the SHA-256 bytes to a lowercase hex string (the challenge hint)

Reconstructed logic:

1) round current unix time down to the current minute
    t60 = (time() // 60) * 60

2) build a 32-bit seed
    seed = (t60 XOR 0xDEADC0DE) & 0xffffffff

3) turn seed into decimal ASCII (no padding)
    s = str(seed)

4) hash it and use the hex digest as an ASCII key (64 chars)
    key_hex = sha256(s).hexdigest()   # lowercase, 64 chars
    key_bytes = key_hex.encode("ascii")

Important detail (the hint): the program uses the hex digest text as the XOR key, not the raw 32-byte hash.

## file encryption
Each file is XOR’d with the repeating 64-byte ASCII key:

    cipher[i] = plain[i] XOR key_bytes[i % 64]

Decryption is identical:

    plain[i] = cipher[i] XOR key_bytes[i % 64]

## recovering the correct minute
The only missing ingredient is the minute value t60 used when the file was encrypted.

Because we have an encrypted flag file and we know the plaintext should look like:
    HACKDAY{...}

we can brute force a reasonable time window by trying each minute, decrypting, and checking for that prefix/suffix.

Bruteforcing around the event timeframe finds:

- t60 = 1769009160
- which is 2026-01-21 15:26:00 UTC

Then:

- seed = (1769009160 XOR 0xDEADC0DE) & 0xffffffff
       = 3084726486

- sha256(str(seed)).hexdigest()
  = ed7c7c496021622ecb293fb542f77c3d2a809f0119277107ce2e4b257a8d6395

Using that 64-character hex string as the repeating XOR key decrypts flag.txt to:
```
    HACKDAY{t1Me_i5_@lwAy5_7h3_keY}
```
## solver script (bruteforce by minute and decrypt)
```python
import hashlib
import datetime
from pathlib import Path

CIPHERTEXT = Path("flag.txt").read_bytes()
MAGIC = 0xDEADC0DE

def key_for_t60(t60: int) -> bytes:
    seed = (t60 ^ MAGIC) & 0xffffffff
    return hashlib.sha256(str(seed).encode("ascii")).hexdigest().encode("ascii")  # 64 bytes

def decrypt_with_t60(t60: int) -> bytes:
    k = key_for_t60(t60)
    return bytes(b ^ k[i % 64] for i, b in enumerate(CIPHERTEXT))

def brute_minutes(start_utc: datetime.datetime, end_utc: datetime.datetime):
    start = int(start_utc.timestamp()) // 60 * 60
    end = int(end_utc.timestamp()) // 60 * 60
    for t60 in range(start, end + 60, 60):
        pt = decrypt_with_t60(t60)
        if pt.startswith(b"HACKDAY{") and pt.rstrip().endswith(b"}"):
            return t60, pt
    return None, None

# adjust the window if needed; this one is wide but still fast
start = datetime.datetime(2025, 12, 1, tzinfo=datetime.timezone.utc)
end   = datetime.datetime(2026, 2, 15, tzinfo=datetime.timezone.utc)

t60, pt = brute_minutes(start, end)
if t60 is None:
    raise SystemExit("not found in range")

print("t60:", t60, "utc:", datetime.datetime.fromtimestamp(t60, tz=datetime.timezone.utc))
seed = (t60 ^ MAGIC) & 0xffffffff
print("seed:", seed)
print("key_hex:", hashlib.sha256(str(seed).encode("ascii")).hexdigest())
print("plaintext:", pt.decode("ascii", errors="replace"))
```
Flag:
HACKDAY{t1Me_i5_@lwAy5_7h3_keY}
