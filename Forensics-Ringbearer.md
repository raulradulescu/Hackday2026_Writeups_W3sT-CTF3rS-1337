# Ringbearer

## Challenge Information
- **Name:** Ringbearer
- **Category:** Forensics / Windows Registry Analysis
- **Event:** Hackday 2026
- **Theme:** Lord of the Rings

## Description

A forensics challenge involving Windows registry analysis. We are given a directory structure mimicking a Windows user profile with Desktop, Documents, Downloads, and System32 folders.

## Initial Reconnaissance

Exploring the challenge files:

```bash
ls -R Ringbearer/
```

The interesting directory is `Ringbearer/Documents/old/` which contains several `.bak` files that appear to be Windows registry hive backups.

## Solution

### Step 1: Identify Registry Hives

The backup files in `Documents/old/` are Windows registry hives with SHA-1 hashes as filenames:

- `f16bed56189e249fe4ca8ed10a1ecae60e8ceac0.bak` - SAM (Security Account Manager) hive
- `317f1e761f2faa8da781a4762b9dcc2c5cad209a.bak` - SYSTEM hive

These files contain Windows user account information including password hashes.

### Step 2: Extract User Information from Old SAM

Using `regipy` to parse the old SAM backup:

```bash
# Install regipy if needed
pip install regipy

# Parse the SAM file
regipy-parse-header f16bed56189e249fe4ca8ed10a1ecae60e8ceac0.bak
```

This reveals a user account: **samwiseg** (a reference to Samwise Gamgee from LOTR).

### Step 3: Compare with Current SAM

Checking the current SAM file in `System32/config/SAM` shows that the `samwiseg` user has been deleted from the current system, but exists in the old backup.

### Step 4: Extract Password Hash

Using `impacket-secretsdump` to extract NTLM hashes from the registry hives:

```bash
# Using WSL with Python virtual environment
impacket-secretsdump -sam f16bed56189e249fe4ca8ed10a1ecae60e8ceac0.bak -system 317f1e761f2faa8da781a4762b9dcc2c5cad209a.bak LOCAL
```

This extracts the NTLM hash for `samwiseg`:
```
samwiseg:1001:aad3b435b51404eeaad3b435b51404ee:dcd99365563e67eb8fbe8c9d83b0ca6c:::
```

The hash is: `dcd99365563e67eb8fbe8c9d83b0ca6c`

### Step 5: Crack the Hash

Using an online service like [CrackStation](https://crackstation.net/) or hashcat:

```bash
# Using hashcat
hashcat -m 1000 -a 0 dcd99365563e67eb8fbe8c9d83b0ca6c wordlist.txt
```

The password is cracked: **TheHelper**

(This is a reference to Samwise being Frodo's helper in LOTR)

### Step 6: Find the Hidden Archive

Searching for password-protected archives:

```bash
find Ringbearer/ -name "*.7z" -o -name "*.zip" -o -name "*.rar"
```

We find a 7z archive (location varies, but likely hidden or in Documents).

### Step 7: Extract with Combined Credentials

The password format follows the pattern: `username@password`

```bash
7z x hidden_archive.7z
# Password: samwiseg@TheHelper
```

### Step 8: Retrieve the Flag

Inside the extracted archive is `flag.txt`:

```
HACKDAY{TH4nk_Y0u_s4M_G4mg3e}
```

## Flag

```
HACKDAY{TH4nk_Y0u_s4M_G4mg3e}
```

## Tools Used

- **regipy** - Python library for parsing Windows registry hives
- **impacket-secretsdump** - Extract credentials from Windows registry hives
- **CrackStation** / **hashcat** - NTLM hash cracking
- **7z** - Archive extraction

## Key Concepts

### Windows SAM and SYSTEM Hives

- **SAM (Security Account Manager)** - Contains user account information and password hashes
- **SYSTEM** - Contains the boot key (SYSKEY) needed to decrypt SAM hashes
- Both files are needed together to extract usable password hashes

### NTLM Hash Format

Windows stores passwords as NTLM hashes. The format extracted by secretsdump is:
```
username:RID:LM_hash:NTLM_hash:::
```

Where:
- `aad3b435b51404eeaad3b435b51404ee` is the empty LM hash (modern Windows)
- `dcd99365563e67eb8fbe8c9d83b0ca6c` is the actual NTLM hash to crack

### Registry Forensics

Old registry backups can contain deleted accounts or previous password hashes, making them valuable for forensic investigations.

## Key Takeaways

1. **Backup files are forensic goldmines** - Old registry backups may contain deleted user accounts and their credentials
2. **SAM + SYSTEM required together** - You need both hives to extract usable hashes
3. **Weak passwords are easily cracked** - Common passwords like "TheHelper" can be cracked instantly
4. **Themed challenges** - The LOTR theme gave hints: Samwise (samwiseg) is known as "The Helper"

## References

- [impacket GitHub](https://github.com/fortra/impacket)
- [regipy Documentation](https://github.com/mkorman90/regipy)
- [Windows Registry Forensics](https://www.sans.org/blog/digital-forensics-windows-registry/)
