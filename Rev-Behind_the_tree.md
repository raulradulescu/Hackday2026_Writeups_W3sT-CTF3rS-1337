# Behind the tree (rev)

## Files

- tree.json: JSON dump of an AST (Clang/LLVM style) for a small C program.
- decoy.txt: space-separated decimal integers (the “gibberish”).

Goal: recover the flag in the format `HACKDAY{sha256}`.

## 1) Understand the program via the AST

We do not have clean C source, only an AST. The plan is:

- Identify file I/O (look for `fopen` calls and the string literals used).
- Identify the transformation (look for an XOR `^` operation).
- Identify any static buffers/arrays initialized with constants (likely the key).

Useful local pokes:

```bash
# list interesting string literals
grep -oE '"[^"]+"' tree.json | sort -u | grep -E 'flag|decoy|fopen'

# find XOR operator nodes (Clang AST JSON typically has "opcode": "^")
grep -n '"opcode": "\\^"' tree.json | head
```

From the AST structure you can confirm the program opens:

- input file: `"flag"` in binary read mode (`"rb"`)
- output file: `"decoy"` in binary write mode (`"wb"`)

## 2) Identify the crypto

Inside the main loop, the AST shows an XOR between an input byte and an element of an array `t` indexed by `i % k`.

That matches a repeating-key XOR:

`y[i] = x[i] ^ t[i % k]`

Decryption is the same operation:

`x[i] = y[i] ^ t[i % k]`

## 3) Recover the key

The AST includes the initializer of the array `t`. The first bytes correspond to ASCII digits:

`9 4 6 6 8 4 8 0 0`

So the key is the byte string:

`b"946684800"`

(There will typically be a trailing `\0` in C, but the effective key length is the digit bytes used by the modulo.)

## 4) Decode `decoy.txt`

`decoy.txt` stores encrypted bytes as decimal integers separated by spaces, so:

1. parse integers
2. XOR each with the key byte (cycling over the key)
3. convert to bytes
4. decode as UTF-8

Decoder:

```py
#!/usr/bin/env python3

key = b"946684800"

with open("decoy.txt", "r", encoding="utf-8") as f:
    data = [int(x) for x in f.read().split()]

pt = bytes([v ^ key[i % len(key)] for i, v in enumerate(data)])
print(pt.decode("utf-8", errors="strict").strip())
```

Running it prints the flag:

`HACKDAY{f19fd5e7114ede733f467959e457775cf35cc9d5ced25a1aff8ac2d8a51c9816}`

## Verification checklist

- Output starts with `HACKDAY{` and ends with `}`.
- Inside braces is 64 hex characters (SHA-256 length).
- Decoder output matches exactly when run against the provided `decoy.txt`.
