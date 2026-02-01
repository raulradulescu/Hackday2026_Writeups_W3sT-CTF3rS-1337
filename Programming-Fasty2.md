# Fasty v2

## Challenge Information
- **Name:** Fasty v2
- **Category:** Programming
- **Event:** Hackday 2026
- **Status:** SOLVED

## Flag
```
HACKDAY{W1N4MP_K1CKS_TH3_455_2000}
```

## Description

The sequel to the Fasty challenge, featuring significantly more complex algorithmic problems. The server (`51.210.244.18:8688`) presents problems ranging from emulating a simple CPU to solving graph traversal and finding internal states of LFSRs.

## Vulnerability Analysis

The challenge requires implementing logic for several distinct mini-games/formats:
1.  **Winamp Playlist**: A checksum validation puzzle where specific playlists map to numeric values. Analysis of an alternative exploit script revealed the checksum is simply the sum of the 1-based alphabetic positions of the characters (A=1, B=2, ..., Z=26).
2.  **Snake**: Calculating the final displacement (Manhattan distance) given a set of moves (UP, DOWN, LEFT, RIGHT).
3.  **Zip**: Implementing Run-Length Encoding (RLE) on strings.
4.  **P2P-Ring**: Simulating message passing in a ring topology to find the node `N` hops away.
5.  **GB-CPU**: Parsing and executing instructions (ADD, SUB, MUL, DIV) on a simple register-based VM.
6.  **LFSR**: Predicting the state of an 8-bit Linear Feedback Shift Register with a specific tap (`0xb8`).
7.  **Maze**: Finding a path of exact length 6 using only two operations: `x*2` (move A) and `3x+1` (move B).
8.  **MSN Encoding**: Decodes "leet" speak or specific mappings.

## Exploit Strategy

The strategy remains similar to Fasty v1: connect, parse, solve, respond. However, the solvers are more sophisticated.

### Key Logic Implementations
- **Winamp**: Algorithmic solution `sum(ord(c)-64)`.
- **Maze Solver**: Uses Breadth-First Search (BFS) to find the sequence of "A" and "B" operations that transform the starting number to the target.
- **LFSR**: Simulation of the bitwise shift and XOR operations.
- **GB-CPU**: A dictionary-based register simulation.

## Full Exploit Script

```python
import re
import hashlib
import socket
import time
import base64
from collections import deque

HOST = "51.210.244.18"
PORT = 8688

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def solve_q1_winamp(playlist: str) -> str:
    # Algorithmic solution: Sum of 1-based alphabetic indices
    total = sum((ord(ch) - ord("A") + 1) for ch in playlist)
    return str(total)

def decode_msn(data: str) -> str:
    d = data.strip().rstrip('=').lower()
    if "f0h4ier" in d: return "SK8ER"
    if "e0ugf1ej" in d: return "WASSUP"
    mapping = {'0': 'A', '1': 'Y', '3': 'E', '4': 'E', '7': 'T', '8': 'B', '9': 'G',
               'e': 'W', 'u': 'S', 'g': 'S', 'f': 'U', 'j': 'C', 'o': 'B', 'x': '3', 'n': 'R', 'r': 'R'}
    res = ""
    for c in d:
        res += mapping.get(c, c.upper())
    return res

def lfsr_8bit(seed: int, steps: int) -> str:
    state = seed
    tap = 0xb8
    for _ in range(steps):
        bit = bin(state & tap).count('1') % 2
        state = ((state << 1) | bit) & 0xFF
    return hex(state)

def solve_maze(target: int) -> str:
    queue = deque([(1, "")])
    while queue:
        curr, path = queue.popleft()
        if curr == target and len(path) == 6:
            return path
        if len(path) >= 6:
            continue
        queue.append((curr * 2, path + "A"))
        queue.append((curr * 3 + 1, path + "B"))
    return "ABABAA"

def solve_question(line: str) -> str | None:
    line = line.strip()
    
    if "Playlist" in line:
        m = re.search(r"\[([A-Z]+)\]", line)
        if m: return solve_q1_winamp(m.group(1))
    
    if "Snake" in line:
        x, y = 0, 0
        moves = re.findall(r"(UP|DOWN|LEFT|RIGHT) (\d+)", line)
        for direction, distance in moves:
            dist = int(distance)
            if direction == "UP": y += dist
            elif direction == "DOWN": y -= dist
            elif direction == "LEFT": x -= dist
            elif direction == "RIGHT": x += dist
        return str(abs(x) + abs(y))
    
    if "Zip" in line:
        m = re.search(r"'([a-z]+)'", line)
        if m:
            d = m.group(1); res = ""; count = 1
            if not d: return ""
            for i in range(1, len(d)):
                if d[i] == d[i-1]: count += 1
                else: res += f"{d[i-1]}{count}"; count = 1
            res += f"{d[-1]}{count}"
            return res
            
    if "P2P-Ring" in line:
        try:
            parts = line.split(':')
            if len(parts) > 1:
                nodes = re.findall(r"([A-Z])", parts[1])
                unique_nodes = []
                for n in nodes:
                    if n not in unique_nodes: unique_nodes.append(n)
                    elif n == unique_nodes[0] and len(unique_nodes) > 1: break
                m = re.search(r"Start ([A-Z]), (\d+) hops", line)
                if m:
                    idx = unique_nodes.index(m.group(1))
                    return unique_nodes[(idx + int(m.group(2))) % len(unique_nodes)]
        except: pass
            
    if "SHA256" in line:
        m = re.search(r"'([^']+)'", line)
        if m: return sha256_hex(m.group(1))
        
    if "GB-CPU" in line:
        m = re.search(r": (.*?)\. Result\?", line)
        if m:
            v_part, o_part = m.group(1).split('|')
            reg = {}
            for match in re.finditer(r"([A-Z])=(\d+)", v_part): reg[match.group(1)] = int(match.group(2))
            for op in o_part.split(','):
                p = op.strip().split()
                cmd, dest = p[0], p[1]
                val = reg[p[2]] if len(p) > 2 and p[2] in reg else int(p[2]) if len(p) > 2 else 0
                if cmd == "ADD": reg[dest] += val
                elif cmd == "SUB": reg[dest] -= val
                elif cmd == "MUL": reg[dest] *= val
                elif cmd == "DIV": reg[dest] //= val
            return str(reg['X'])
            
    if "MSN Encoding" in line:
        m = re.search(r"'([^']+)'", line)
        if m: return decode_msn(m.group(1))
        
    if "LFSR" in line:
        m = re.search(r"Seed (0x[0-9a-fA-F]+)\. State after (\d+) shifts\?", line)
        if m: return lfsr_8bit(int(m.group(1), 16), int(m.group(2)))
        
    if "Maze" in line:
        m = re.search(r"Target: (\d+)", line)
        if m: return solve_maze(int(m.group(1)))
        
    return None

def run_once():
    try:
        with socket.create_connection((HOST, PORT), timeout=10.0) as sock:
            print("[*] Connected to F4STY")
            buf = ""
            while True:
                chunk = sock.recv(4096).decode(errors="ignore")
                if not chunk: break
                print(chunk, end="", flush=True)
                buf += chunk
                
                if "HACKDAY{" in buf:
                    if "}" not in buf: continue
                    print("\n[!!!] FLAG FOUND [!!!]")
                    flag_m = re.search(r"HACKDAY\{.*?\}", buf)
                    if flag_m:
                        print(f"Captured: {flag_m.group(0)}")
                        return True
                    else: return True

                if ">" in buf:
                    lines = buf.splitlines()
                    q_line = None
                    for ln in reversed(lines):
                        if "[Q" in ln and "]" in ln:
                            q_line = ln
                            break
                    if q_line:
                        ans = solve_question(q_line)
                        if ans:
                            sock.sendall((ans + "\n").encode())
                        buf = ""
            return False
    except Exception as e:
        print(f"\n[!] Error: {e}")
        return False
    
def main():
    attempt = 1
    while True:
        print(f"\n[*] Attempt #{attempt}")
        if run_once():
            break
        attempt += 1
        time.sleep(1)

if __name__ == "__main__":
    main()
```

## Key Takeaways

1.  **Complexity Scaling**: Automated challenges can scale in difficulty by introducing varied problem types that require implementing distinct logic (graph algorithms, emulation, crypto) rather than just parsing.
2.  **Pre-computation**: Some problems (like the Winamp checksum) might require off-line analysis or pre-computing tables if the logic isn't immediately obvious.
3.  **Robust Parsing**: Handling multi-line outputs and various data formats is critical for stability.

## Tools Used

- **Python** - Scripting.
- **socket** - Network communication.
- **deque** - Efficient queue for BFS.
