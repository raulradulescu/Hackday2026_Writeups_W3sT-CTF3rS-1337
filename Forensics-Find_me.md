# find_me - Hackday 2026 CTF Writeup

## Challenge Information
- **Name:** find_me
- **Category:** Forensics
- **Points:** 456
- **Difficulty:** Hard
- **Event:** Hackday 2026

## Description

> My little brother has been playing with the family computer again. I don't know what he did, but he opened a black window with lots of green text and started banging away at the keyboard, saying he was "coding a video game".
>
> Now I can't find the files anywhere.
>
> *fragmented into 8 parts*

## Challenge Files

- `image.qcow2` - QEMU disk image (2.26 GiB actual, 20 GiB virtual)

## Initial Analysis

### Converting the Disk Image

First, we converted the QCOW2 image to raw format for analysis:

```bash
qemu-img convert -f qcow2 -O raw image.qcow2 /tmp/image.raw
```

### Partition Layout

```bash
mmls /tmp/image.raw
```

```
DOS Partition Table
      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0036132863   0036130816   Linux (0x83)
003:  000:001   0036132864   0041940991   0005808128   Linux Swap / Solaris x86 (0x82)
```

### Extracting the Linux Partition

```bash
dd if=/tmp/image.raw of=/tmp/partition.raw bs=512 skip=2048 count=36130816
```

### Filesystem Information

The partition contains an ext4 filesystem with extended attribute support enabled:

```bash
debugfs /tmp/partition.raw -R "feature"
# Filesystem features: ext_attr resize_inode dir_index filetype sparse_super large_file
```

## Key Findings

### User Files

```bash
fls -rp /tmp/partition.raw | grep home
```

Found in `/home/user/`:
- `note.txt` - Contains: "I have the feeling that someone has done something really nasty to my file system."
- `.bash_history` - Empty (1 byte)

Also found `/var/lib/dhcpcd/secret` containing 64 bytes of hex-encoded data.

### Orphan Blocks Discovery

Based on the challenge hint "fragmented into 8 parts", we searched for orphan blocks (allocated but not linked to any file) containing short text strings:

```python
# Search for blocks with text followed by nulls (orphan pattern)
for block_num in range(num_blocks):
    first_bytes = read_block(block_num)[:32]
    null_pos = first_bytes.find(b'\x00')
    if 0 < null_pos <= 20:
        text = first_bytes[:null_pos]
        if is_printable_ascii(text) and rest_is_null(first_bytes[null_pos:]):
            # Found orphan-like block
```

### Flag Markers Found

- **Block 27265**: `HACKDAY{` (flag start)
- **Block 103541**: `}` (flag end)

### Hex Fragments Found

Multiple hex-like strings in orphan blocks:

| Block | Content | Length |
|-------|---------|--------|
| 12514 | 4805c5d | 7 |
| 23855 | 51aa49 | 6 |
| 25755 | 5024aeb | 7 |
| 26044 | bcd0d68 | 7 |
| 26898 | c64551 | 6 |
| 36379 | 5b069bc | 7 |
| 44988 | 71dcfb | 6 |
| 61387 | ef599c | 6 |
| 96737 | 016f90 | 6 |
| 178555 | 73b05d | 6 |

## Extended Attributes Investigation

The challenge mentioned "coding a video game", suggesting extended attributes named `user.game1` through `user.game8` might store the flag fragments.

### Exhaustive Search

We performed a complete scan of all inodes for extended attributes:

```python
# Scanned all 1,130,496 inodes
# Checked both inline xattrs and external xattr blocks (i_file_acl)
# Searched for any attribute containing "game" in the name
```

**Result:** Only 1 user.* extended attribute found in the entire filesystem:
- `user.random-seed-creditable` on inode 196622

No `game`-related extended attributes were discovered despite extensive searching.

## Attempted Solutions

### Approach 1: Orphan Blocks Between Markers

Using hex fragments between `HACKDAY{` (block 27265) and `}` (block 103541):

```
HACKDAY{5b069bc71dcfbef599c016f90}
```

**Result:** Incorrect

### Approach 2: Orphan Blocks Before Markers

Using hex fragments from blocks before the opening marker:

```
HACKDAY{4805c5d51aa495024aebbcd0d68c64551}
```

**Result:** Incorrect

## Tools Used

- **qemu-img** - Disk image conversion
- **The Sleuth Kit (TSK)** - `fls`, `icat`, `mmls` for filesystem analysis
- **debugfs** - ext4 filesystem debugging and xattr inspection
- **Python** - Custom scripts for block scanning and pattern matching
- **strings/grep** - String extraction and searching

## Status

**NOT SOLVED** - The correct combination of fragments or the method to find the `game`-related extended attributes was not determined.

## Notes for Future Reference

1. The challenge strongly hints at extended attributes with "game" in the name
2. The flag is "fragmented into 8 parts" (HACKDAY{ + 6 fragments + })
3. Standard xattr scanning tools did not reveal game-named attributes
4. The fragments may require a specific ordering mechanism we didn't discover
5. There may be a custom xattr storage method or encoding not found by standard tools

## Lessons Learned

1. Extended attributes in ext4 can be stored inline in inodes or in external blocks
2. Orphan blocks (allocated but unlinked) can hide data in filesystems
3. The `debugfs` tool's `ea_list` and `ea_get` commands are useful for xattr inspection
4. Sometimes the intended solution path differs significantly from what forensic analysis reveals
