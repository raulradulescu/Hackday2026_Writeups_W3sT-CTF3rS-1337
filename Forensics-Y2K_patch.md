# Y2K Patch - Hackday 2026 CTF Writeup

## Challenge Information
- **Name:** Y2K Patch
- **Category:** Crypto / Forensics
- **Event:** Hackday 2026

## Description

We are provided with an encrypted ZIP file (`export.zip`) that contains a file called `Y2K_PATCH.bin`. The ZIP file uses ZipCrypto encryption, which is vulnerable to known-plaintext attacks.

## Solution

### Step 1: Identify the Encryption

First, we examine the ZIP file to understand its structure:

```bash
7z l export.zip
```

The archive contains encrypted files using ZipCrypto (the legacy ZIP encryption method).

### Step 2: Find Known Plaintext

For a known-plaintext attack on ZipCrypto, we need at least 12 bytes of known plaintext from one of the files in the archive. 

In this case, we had access to a file `to-do_list.txt` that was also present in the encrypted archive. This file serves as our known plaintext.

### Step 3: Use bkcrack for Known-Plaintext Attack

[bkcrack](https://github.com/kimci86/bkcrack) is a tool that implements the Biham and Kocher known-plaintext attack against ZipCrypto.

First, we create a plaintext ZIP with our known file:

```bash
zip plaintext.zip to-do_list.txt
```

Then we run bkcrack to recover the internal keys:

```bash
bkcrack -C export.zip -c to-do_list.txt -P plaintext.zip -p to-do_list.txt
```

This recovers the three 32-bit internal keys used by ZipCrypto.

### Step 4: Extract the Files

Once we have the keys, we can decrypt the archive. We have two options:

**Option A:** Create a new ZIP with a known password:
```bash
bkcrack -C export.zip -k <key1> <key2> <key3> -U decrypted.zip newpassword
```

Then extract normally:
```bash
unzip decrypted.zip
# Password: newpassword
```

**Option B:** Directly decrypt and extract:
```bash
bkcrack -C export.zip -c Y2K_PATCH.bin -k <key1> <key2> <key3> -d Y2K_PATCH.bin
```

### Step 5: Retrieve the Flag

After decryption, we examine the `Y2K_PATCH.bin` file to find the flag:

```bash
strings Y2K_PATCH.bin | grep -i hackday
# or
cat Y2K_PATCH.bin
```

## Flag

```
HACKDAY{...}
```

## Tools Used

- **bkcrack v1.7.0** - Known-plaintext attack on ZipCrypto
- **7z** - ZIP file analysis
- **strings** - Binary analysis

## Key Takeaways

1. **ZipCrypto is insecure** - The legacy ZIP encryption (ZipCrypto/PKZIP) is vulnerable to known-plaintext attacks and should never be used for sensitive data.

2. **Known-plaintext attacks** - If an attacker knows or can guess at least 12 bytes of plaintext from any file in the archive, they can recover the encryption keys and decrypt the entire archive.

3. **Use AES encryption** - Modern ZIP implementations support AES-256 encryption which is not vulnerable to this attack. Always use `-em=AES256` when creating encrypted archives.

## References

- [bkcrack GitHub Repository](https://github.com/kimci86/bkcrack)
- [Biham & Kocher - A Known Plaintext Attack on the PKZIP Stream Cipher](https://link.springer.com/chapter/10.1007/3-540-60590-8_12)
