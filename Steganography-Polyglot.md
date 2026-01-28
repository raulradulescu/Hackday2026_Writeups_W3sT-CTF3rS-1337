# Polyglot - writeup
- Description: It must be so cool to be able to read all those types of languages!

## Challenge
We are given a file `challenge.pdf` (hash provided by the platform). The goal is to extract the flag in format:

HACKDAY{flag}

The hint strongly suggests that the file is not “just a PDF”, but something that can be interpreted as multiple formats (a polyglot), or it contains hidden embedded data.

## Step 1: Check whether the PDF contains extra embedded data
A classic CTF trick is to append a second file format after the legitimate PDF end. Many parsers ignore trailing bytes, so a PDF viewer shows a normal document while forensic tooling reveals extra content.

The fastest checks:

- `binwalk challenge.pdf` (look for embedded signatures like ZIP/PNG)
- `strings -n 6 challenge.pdf | less` (sometimes filenames pop out)
- search for ZIP magic bytes `PK\x03\x04`

## Step 2: Identify a ZIP appended to the PDF
A ZIP archive starts with the signature:

PK\x03\x04

If that signature appears inside the PDF (especially near the end), it usually means a ZIP was appended or embedded.

We locate the offset of that signature and carve everything from there into a new file, which should be a valid ZIP.

## Step 3: Carve and extract the appended ZIP
Once we carve out the ZIP and unzip it, we get a file (in this challenge it’s an image) containing the flag.

One clean reproduction approach:

```
binwalk -e challenge.pdf
```

If you want to do it manually and be explicit about offsets:

```py
data = open("challenge.pdf","rb").read()
off = data.find(b"PK\x03\x04")
print("zip_offset =", off)
open("carved.zip","wb").write(data[off:])
```

```bash
unzip carved.zip
ls -la
```

## Step 4: Read the flag from the extracted file
The ZIP contains `flag.png` (or similarly named). Opening the image reveals the flag text.

The correct flag (note the letter “l” vs “I” ambiguity that OCR often messes up):

HACKDAY{FiLes_can_B3_PolY6LOT}

## Notes on why OCR can lie here
The extracted image contains mixed-case characters. OCR commonly confuses:
- l (lowercase L) vs I (uppercase i)
- O vs 0
- Y vs V

So the correct method is to extract the hidden file and read it directly, not rely on OCR output alone.

## Final flag
HACKDAY{FiLes_can_B3_PolY6LOT}
