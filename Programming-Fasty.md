# Fasty

## Challenge Information
- **Name:** Fasty
- **Category:** Programming
- **Event:** Hackday 2026
- **Status:** SOLVED

## Flag
```
HACKDAY{7777_LEGACY_OK}
```

## Description

A classic "PPC" (Professional Programming Challenge) where the server sends a series of algorithmic and logic questions that must be answered instantly. The questions range from simple arithmetic to cryptographic hashing and string manipulation.

## Vulnerability Analysis

### Challenge Logic
The server (`51.210.244.18:8677`) opens a TCP socket and streams text. The prompt ends with `?` or `>`. The types of questions observed include:
1.  **Arithmetic**: `Q1: 10 + 20 ?`
2.  **String Reversal**: `Reverse this string: '...'`
3.  **SHA256**: `SHA256 hash (hex) of '...'`
4.  **List Operations**: Finding the smallest number or filtering words by length.
5.  **Bitwise Operations**: XOR calculations.
6.  **Encoding/Ciphers**: Caesar cipher (+3), Binary conversion, internal Hamming weight.
7.  **MAC Formatting**: Formatting hex strings as MAC addresses.

### Solution Approach
Since the time limit for each question is very short, manual entry is impossible. The solution requires a Python script using `socket` to connect and `re` (regular expressions) to parse the variable prompts and extract values.

## Exploit Strategy

1.  **Connect** to the server socket.
2.  **Buffer** the incoming data until a question prompt is detected.
3.  **Parse** the question type using Regex to identify the operation needed.
4.  **Compute** the result (e.g., `hashlib.sha256`, `int(str, 2)`, etc.).
5.  **Send** the answer back followed by a newline.
6.  **Repeat** until the flag is printed.

## Full Exploit Script

```python
#!/usr/bin/env python3
import re
import hashlib
import socket
import time
import sys

HOST = "51.210.244.18"
PORT = 8677

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def caesar_plus3(s: str) -> str:
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + 3) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + 3) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)

def hamming_weight(n: int) -> int:
    try:
        return n.bit_count()
    except AttributeError:
        return bin(n).count("1")

def to_mac(hexstr: str) -> str:
    hexstr = hexstr.strip().lower()
    if len(hexstr) % 2 != 0:
        hexstr = "0" + hexstr
    pairs = [hexstr[i:i+2] for i in range(0, len(hexstr), 2)]
    return ":".join(pairs)

def solve_question(line: str) -> str | None:
    line = line.strip()

    # Q1: 947 - 460 ?
    m = re.search(r"Q\d+:\s*(-?\d+)\s*([\+\-\*/])\s*(-?\d+)\s*\?", line)
    if m:
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        if op == "+": return str(a + b)
        if op == "-": return str(a - b)
        if op == "*": return str(a * b)
        if op == "/": return str(a // b)

    # Reverse this string:
    m = re.search(r"Reverse this string:\s*'([^']*)'", line)
    if m:
        return m.group(1)[::-1]

    # SHA256
    m = re.search(r"SHA256 hash \(hex\) of\s*'([^']*)'", line)
    if m:
        return sha256_hex(m.group(1))

    # Smallest number
    m = re.search(r"smallest number in\s*\[([0-9,\s-]+)\]", line)
    if m:
        nums = [int(x.strip()) for x in m.group(1).split(",") if x.strip()]
        return str(min(nums))

    # Words > 5 chars (adjust regex for > N)
    m = re.search(r"From\s*\[(.*)\],\s*keep only words\s*>\s*(\d+) chars", line)
    if m:
        inside, lim = m.group(1), int(m.group(2))
        words = re.findall(r"'([^']*)'", inside)
        return ",".join([w for w in words if len(w) > lim])

    # 4167 XOR 5306
    m = re.search(r"What is\s*(\d+)\s*XOR\s*(\d+)\s*\(decimal\)\?", line, re.IGNORECASE)
    if m:
        return str(int(m.group(1)) ^ int(m.group(2)))

    # Caesar +3
    m = re.search(r"Apply Caesar cipher\s*\(\+(\d+)\)\s*to\s*'([^']*)'", line)
    if m:
        return caesar_plus3(m.group(2))

    # Hamming weight
    m = re.search(r"Hamming weight of\s*(\d+)\?", line, re.IGNORECASE)
    if m:
        return str(hamming_weight(int(m.group(1))))

    # Binary
    m = re.search(r"Convert\s*(\d+)\s*to binary\s*\(bits only\)", line, re.IGNORECASE)
    if m:
        return bin(int(m.group(1)))[2:]

    # MAC
    m = re.search(r"Format\s*'([0-9a-fA-F]+)'\s*as a MAC address", line, re.IGNORECASE)
    if m:
        return to_mac(m.group(1))

    return None

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((HOST, PORT))
        print("[*] Connected")
        
        buf = ""
        while True:
            try:
                chunk = s.recv(1024)
                if not chunk:
                    break
                decoded = chunk.decode(errors="ignore")
                print(decoded, end="", flush=True)
                buf += decoded

                if ">" in buf or "?" in buf:
                     qs = list(re.finditer(r"(Q\d+:.*?(\?|chars|address|'|\]))", buf, re.DOTALL))
                     if qs:
                         last_match = qs[-1]
                         q_full = last_match.group(1)
                         
                         ans = solve_question(q_full)
                         if ans:
                             time.sleep(0.2)
                             s.sendall((ans + "\n").encode())
                             buf = "" 
                         
            except Exception as e:
                print(e)
                break
    except KeyboardInterrupt:
        print("\n[*] Exiting")
    finally:
        s.close()

if __name__ == "__main__":
    main()
```

## Key Takeaways

1.  **Regex is Essential**: Parsing unstructured but predictable text output often relies on robust regular expressions.
2.  **Socket Handling**: Dealing with partial packets and buffering is necessary when interfacing with a raw TCP server.
3.  **Speed**: Python's `socket` library is fast enough for most CTF challenges, but introducing small delays (e.g., `time.sleep(0.2)`) can sometimes help with server stability or anti-cheat rate limits.

## Tools Used

- **Python** - Scripting.
- **socket** - Network communication.
- **re** - Regular expressions.
