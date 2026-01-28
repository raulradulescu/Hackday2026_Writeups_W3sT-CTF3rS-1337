# The Glitch in the Matrix

## Description
- The simulation is starting to fracture, and Neo can finally see the raw data stream behind the reality. During a "bullet time" glitch, he noticed that the truth isn't hidden in the whole image, but scattered within the tiniest fragments of the red signals.

- Morpheus left a final transmission: "To escape, you must look closely at the red pill. Collect its smallest units of information and regroup them 8 by 8 to reconstruct the message. But remember, the signal is still distorted. Only the Answer to the Ultimate Question of Life, the Universe, and Everything can unmask the final secret".

- Can you help Neo decode reality and escape the Matrix?

## Next steps

Given the description of the challenge, we can use our CTF intuition to solve it:
- "he noticed that the truth isn't hidden in the whole image, but scattered within the tiniest fragments" -> hints to LSB steganography
- "but scattered within the tiniest fragments of the red signals" -> Red channel LSB steganography
- " you must look closely at the red pill. Collect its smallest units of information and regroup them 8 by 8 to reconstruct the message" -> should confirm red channel only LSB steganography
- "Only the Answer to the Ultimate Question of Life, the Universe, and Everything can unmask the final secret." -> this is 42

## How to solve

Given those hints in the description we opened up Cyberchef, uploaded the picture and chose LSB and XOR operations.

We chose only red channel for decoding and we XOR-ed with 0x42 and we had our flag:
```
HACKDAY{e3a12b9383038b0c6d755bcb39d3bf879cac3750588226ba1c52d64fde0a7c96}
```