# NewCrypto (intro) writeup

## Challenge
We are given a file whose content looks like a flag-ish string, but not in the required format:

RISGXIY{SLC_FCPXEC_2004}

We know the real flag format must start with:

HACKDAY{...}

The hint says: "math unlocks it", which suggests a simple classical cipher with a small keyspace and a known-plaintext anchor.

## Observation: the prefix is a perfect known-plaintext crib
If the ciphertext begins with "RISGXIY{", and the plaintext must begin with "HACKDAY{", then we get 6 direct letter mappings:

R -> H
I -> A
S -> C
G -> K
X -> D
I -> A  (again)

That is enough to solve an affine substitution (a common “mathy” monoalphabetic cipher).

## Model: affine cipher on letters A..Z
Map letters to numbers with A=0, B=1, ..., Z=25.

Assume an affine mapping from ciphertext letter c to plaintext letter p:

p ≡ a*c + b (mod 26)

We can solve for a and b using two letter pairs from the known prefix.

Take:
R -> H
I -> A

Convert to numbers:
R = 17, H = 7
I = 8,  A = 0

So we have:
a*17 + b ≡ 7 (mod 26)
a*8  + b ≡ 0 (mod 26)

Subtract the second from the first:
a*(17-8) ≡ 7-0 (mod 26)
a*9 ≡ 7 (mod 26)

Now invert 9 modulo 26.
9*3 = 27 ≡ 1 (mod 26), so 9^{-1} ≡ 3.

Thus:
a ≡ 7 * 3 ≡ 21 (mod 26)

Plug back to find b using a*8 + b ≡ 0:
21*8 = 168
b ≡ -168 ≡ 14 (mod 26)

So the decryption mapping is:
p ≡ 21*c + 14 (mod 26)

## Decode the payload
Apply p = (21*c + 14) mod 26 to every A–Z character in the ciphertext, leaving underscores, digits, and braces unchanged.

This transforms:
RISGXIY{SLC_FCPXEC_2004}
into:
HACKDAY{CLE_PERDUE_2004}

So the flag is:

HACKDAY{CLE_PERDUE_2004}

## Reference implementation (Python)
```py
cipher = "RISGXIY{SLC_FCPXEC_2004}"
a, b = 21, 14
A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def dec(ch):
    up = ch.upper()
    if up in A:
        c = A.index(up)
        p = (a*c + b) % 26
        out = A[p]
        return out if ch.isupper() else out.lower()
    return ch

print("".join(dec(ch) for ch in cipher))
```
