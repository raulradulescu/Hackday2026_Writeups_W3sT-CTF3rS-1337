# The Lotery

## Challenge Information
- **Category**: Web / WASM
- **Challenge**: The Lotery
- **Difficulty**: Medium
- **URL**: https://4ey7oup3c2.hackday.fr

## Challenge Description
> While rummaging through your grandfather's dusty attic, you stumbled upon a strange, vintage handheld console. It's running an old arcade "scratch-off" game called Wipin'. Your grandfather left a note attached to it:
>
> "I've spent years on this, but it seems impossible to hit the jackpot. No matter how fast I wipe, the high score stays just out of reach. There's a hidden prize for the winners, but the machine feels rigged... Take a look at it, maybe you can find what I couldn't."
>
> Can you dive into the machine's code, bypass the mechanics, and claim the ultimate flag?

## Initial Reconnaissance

Visiting the URL shows a web-based game compiled using Emscripten (C/C++ to WebAssembly). The page loads several key files:
- `index.html` - Main page
- `index.js` - Emscripten loader/runtime
- `index.wasm` - Compiled WebAssembly binary
- `index.data` - Preloaded data package

## Analysis

### Examining the JavaScript Loader

Looking at `index.js`, we can see the Emscripten file packaging system. The code reveals that files are preloaded into the virtual filesystem:

```javascript
{
  "files": [
    {
      "filename": "/flag.txt",
      "start": 0,
      "end": 30,
      "audio": 0
    }
  ],
  "remote_package_size": 30,
  "package_uuid": "..."
}
```

This metadata shows that:
- A file named `/flag.txt` exists in the virtual filesystem
- It occupies bytes 0-30 in the `index.data` file
- The entire data package is exactly 30 bytes

### Understanding Emscripten File Packaging

Emscripten can bundle data files into the compiled application using the `--preload-file` flag. These files are packaged into `.data` files that are loaded at runtime and mounted into a virtual filesystem accessible by the WASM code.

The key insight is that **the flag is literally embedded as plain data** in the `index.data` file!

## Exploitation

Since the flag is stored in plaintext in the data package, no exploitation is needed. We simply need to:

1. Download the `index.data` file
2. Extract the first 30 bytes (as indicated by the metadata)
3. Read the flag

### Method 1: Using curl and head

```bash
curl -s https://4ey7oup3c2.hackday.fr/index.data | head -c 30
```

Output:
```
HACKDAY{W4SM_BUFF3R_0V3RFL0W}
```

### Method 2: Using wget and dd

```bash
wget -q https://4ey7oup3c2.hackday.fr/index.data -O - | dd bs=1 count=30 2>/dev/null
```

### Method 3: Python script

```python
import requests

response = requests.get('https://4ey7oup3c2.hackday.fr/index.data')
flag = response.content[:30].decode('utf-8', errors='ignore')
print(flag)
```

## Why This Works

The challenge name "The Lotery" and the description about finding something hidden suggest we need to look beyond the game mechanics. The grandfather's note mentions the game is "rigged" - a hint that we shouldn't try to win legitimately.

Instead of playing the game (which might be impossible or require reverse engineering the WASM), we can:
1. Inspect the web assets
2. Find the data package
3. Extract the flag directly from the preloaded files

This is a common web challenge pattern where:
- Client-side validation is bypassed
- Static assets contain secrets
- Metadata reveals file structure
- Direct extraction beats game-play exploitation

## Flag

```
HACKDAY{W4SM_BUFF3R_0V3RFL0W}
```

## Key Takeaways

1. **Check Static Assets**: Web challenges often hide flags in CSS, JS, images, or data files
2. **Read Documentation**: Understanding Emscripten's file packaging revealed the solution
3. **Metadata is Information**: The `index.js` file told us exactly where to look
4. **Don't Overthink**: Sometimes the simplest solution (downloading a file) is correct
5. **Client-Side is Untrusted**: Any data in the browser can be accessed by users

## Tools Used

- `curl` - Download files
- `head` - Extract specific bytes
- Browser DevTools - Inspect network traffic and JavaScript

## Mitigation

For developers:
- Never embed secrets in client-side code or data
- Use server-side validation for game logic
- Implement proper access controls
- Don't rely on obfuscation (WASM, minification) for security
- Store flags server-side and validate actions before revealing them
