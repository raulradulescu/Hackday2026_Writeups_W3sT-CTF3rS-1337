# Epoch Guardian

## Challenge Information
- **Name:** Epoch Guardian
- **Category:** Web
- **Event:** Hackday 2026
- **Status:** SOLVED

## Flag
```
HACKDAY{9ed0a607d4f2e0b9b5ee428fd925280b9f63bed81e0b90c1f135ca41c69b774a}
```

## Description

The challenge presented a chatbot named "Guardian of Époch" that protected accessing the system. To proceed, the user was required to present a "Sigil of Destiny" in a specific format: `SIGIL:<FRAG_A>-<FRAG_B>-<FRAG_C>`. The goal was to find the three hidden fragments scattered across the web server.

## Vulnerability Analysis

### Information Leakage via Metadata and Comments
The application suffered from multiple information leakage vulnerabilities:
1.  **HTML Comments**: Sensitive data (Fragment A) was left in the source code comments, a common oversight in development.
2.  **Custom HTTP Headers**: Fragment C was hidden in a custom header (`x-epoch-heartbeat`) on a specific endpoint (`/healthz`).
3.  **Predictable File Paths**: Fragment B was located in `/rules.txt`, a standard file location for crawler directives (similar to `robots.txt`), which was hinted at by the UI.

## Exploit Strategy

### Step 1: Fragment A - Source Code Inspection
The chatbot hinted at "FRAG_A". Inspecting the HTML source code of the main page revealed the first fragment hidden inside a large block of whitespace/comments near the bottom.
**Value**: `a9f3c1e8b2d4`

### Step 2: Fragment C - HTTP Header Analysis
The bot mentioned "FRAG_C is attached to the system heartbeat". The website had a "Heartbeat" link pointing to `/healthz`. Inspecting the HTTP response headers for this endpoint via DevTools or `curl` revealed the fragment.
**Header**: `x-epoch-heartbeat: c4b7aa10d92f`

### Step 3: Fragment B - Standard File Enumeration
The bot mentioned "FRAG_B" and the UI had a link labeled "Crawler Rules txt" that was broken (pointing to `/`). Guessing standard filenames for crawler rules led to checking `/rules.txt`, which existed and contained the fragment.
**Value**: `5e7d0c19fa33`

### Step 4: Constructing the Sigil
Combining the found fragments into the required format:
`SIGIL:a9f3c1e8b2d4-5e7d0c19fa33-c4b7aa10d92f`

Sending this message to the chatbot unlocked the system and revealed the flag.

## Key Takeaways

1.  **Always Check Source Code**: Developers often leave comments or unused code that leaks information.
2.  **Inspect HTTP Headers**: Custom headers can carry debug info or secrets.
3.  **Fuzzing Standard Files**: Checking for common files like `robots.txt`, `sitemap.xml`, or `rules.txt` is a standard reconnaissance step.

## Tools Used

- **Browser DevTools** - Inspecting source and network headers.
- **Curl** - Fetching headers manually.
