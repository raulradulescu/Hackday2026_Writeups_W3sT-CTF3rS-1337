# HTTPS is the Most Secure Browsing - Writeup

**Challenge Name:** https_is_the_most  
**Category:** Network Security / Cryptography  
**Flag:** `HACKDAY{pRn9_1S_wE@K_AsF_no?}`

## Challenge Description

The challenge provides a packet capture file (`capture.pcap`) containing encrypted HTTPS traffic. The goal is to decrypt the TLS traffic and recover the flag.

## Initial Analysis

### Examining the PCAP

First, I analyzed the capture file using `tshark` to understand what we're working with:

```bash
tshark -r capture.pcap -Y "tls.handshake.type == 11" -T fields -e tls.handshake.certificate
```

This revealed TLS handshake traffic with certificate exchanges.

### Identifying the Cipher Suite

Next, I checked what cipher suite was negotiated:

```bash
tshark -r capture.pcap -Y "tls.handshake.type == 2" -T fields -e tls.handshake.ciphersuite
```

**Result:** `0x002f` = `TLS_RSA_WITH_AES_128_CBC_SHA`

This is crucial! The `TLS_RSA` prefix means this cipher suite uses **RSA key exchange** (not ephemeral Diffie-Hellman). This means:
- The server's private RSA key is used to decrypt the pre-master secret
- If we have the server's private key, we can decrypt all the traffic
- Modern TLS uses ephemeral key exchange (ECDHE/DHE) to prevent this, but older configurations are vulnerable

## The Breakthrough: Certificate Analysis

### Extracting the Certificate

I extracted the server certificate from the PCAP:

```bash
tshark -r capture.pcap -Y "tls.handshake.type == 11" -T fields -e tls.handshake.certificate | xxd -r -p > server_cert.der
openssl x509 -inform DER -in server_cert.der -text
```

### The Critical Clue

The certificate revealed something very interesting:

```
Issuer: CN = New Debian Etch
Subject: CN = New Debian Etch
```

**"Debian Etch"** - This immediately rang alarm bells! Debian Etch was the version affected by one of the most infamous security vulnerabilities in modern cryptography.

## The Vulnerability: CVE-2008-0166

### What is CVE-2008-0166?

In 2008, it was discovered that Debian's OpenSSL package had a critical flaw in its random number generator (PRNG). A well-intentioned code cleanup in 2006 accidentally removed the primary source of entropy, leaving the RNG with only:

- The process ID (PID) - limited to ~32,000 values
- Architecture (32-bit vs 64-bit)

This meant that **all keys generated on affected Debian/Ubuntu systems between 2006-2008 could only come from ~32,767 possible states**.

### Impact

Every SSH key, SSL certificate, and cryptographic key generated on these systems was predictable. Security researchers generated all possible weak keys and published them as a reference database.

## Exploitation

### Step 1: Extract the Public Key Modulus

I extracted the RSA public key modulus from the certificate:

```bash
openssl x509 -inform DER -in server_cert.der -noout -modulus
```

This gave me the public key that was used in the TLS handshake.

### Step 2: Clone the Weak Keys Database

The weak Debian keys were documented and are available on GitHub:

```bash
git clone https://github.com/g0tmi1k/debian-ssh
```

This repository contains:
- All possible weak RSA keys (in various sizes: 1024, 2048, 4096 bits)
- Organized by key fingerprint/modulus patterns

### Step 3: Find the Matching Private Key

I wrote a Python script to search through the weak keys database and find which one matches our certificate:

```python
import subprocess
import os

# Extract modulus from our certificate
cert_modulus_output = subprocess.check_output([
    "openssl", "x509", "-inform", "DER", "-in", "server_cert.der", 
    "-noout", "-modulus"
]).decode().strip()
cert_modulus = cert_modulus_output.split('=')[1]

# Search through weak RSA keys
weak_keys_path = "debian-ssh/common_keys/rsa"

for filename in os.listdir(weak_keys_path):
    if not filename.endswith('.pub'):
        continue
    
    pub_key_path = os.path.join(weak_keys_path, filename)
    
    try:
        # Extract modulus from weak key
        key_modulus_output = subprocess.check_output([
            "ssh-keygen", "-f", pub_key_path, "-e", "-m", "PKCS8"
        ], stderr=subprocess.DEVNULL).decode()
        
        # Convert to PEM and extract modulus
        pem_output = subprocess.check_output([
            "openssl", "rsa", "-pubin", "-text", "-noout"
        ], input=key_modulus_output.encode(), stderr=subprocess.DEVNULL).decode()
        
        # Extract hex modulus
        modulus_hex = ''.join(pem_output.split('Modulus:')[1].split('Exponent:')[0].split())
        modulus_hex = modulus_hex.replace(':', '')
        
        if modulus_hex.upper() == cert_modulus.upper():
            print(f"MATCH FOUND: {filename}")
            break
            
    except:
        continue
```

**Match found:** `9786b8ef0f79a2c3038245d1391fa62c-27191`

This indicates the key was generated with **PID 27191** on the vulnerable Debian system.

### Step 4: Convert to PEM Format

The weak keys are in SSH format, but `tshark` needs PEM format for TLS decryption:

```bash
# Convert public key to PEM
ssh-keygen -f 9786b8ef0f79a2c3038245d1391fa62c-27191.pub -e -m PKCS8 > temp_pub.pem

# Private key is already available
cp 9786b8ef0f79a2c3038245d1391fa62c-27191 weak_private_key
chmod 600 weak_private_key

# Convert SSH private key to RSA PEM format
ssh-keygen -p -m PEM -f weak_private_key -N ""
```

### Step 5: Decrypt the TLS Traffic

With the private key in hand, I used `tshark` to decrypt the HTTPS traffic:

```bash
tshark -r capture.pcap \
    -o "tls.keys_list:0.0.0.0,443,http,weak_private_key" \
    -Y "http" \
    -T fields -e http.file_data | xxd -r -p
```

The `-o tls.keys_list` option tells tshark:
- IP: `0.0.0.0` (any server)
- Port: `443`
- Protocol: `http`
- Key file: `weak_private_key`

### Step 6: Extract the Flag

The decrypted HTTP response contained HTML with the flag:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Secure Page</title>
</head>
<body>
    <h1>Welcome to the secure page!</h1>
    <p>Flag: HACKDAY{pRn9_1S_wE@K_AsF_no?}</p>
</body>
</html>
```

## Key Lessons

1. **Cipher Suite Matters**: Using RSA key exchange (instead of ephemeral DH/ECDHE) means the private key can decrypt past traffic. This is why Perfect Forward Secrecy is critical.

2. **Entropy is Everything**: The Debian OpenSSL vulnerability showed how critical proper random number generation is. Without sufficient entropy, all cryptography fails.

3. **Legacy Systems are Dangerous**: Systems using old TLS configurations with RSA key exchange are vulnerable to this type of attack if keys are compromised.

4. **Certificate Inspection**: Small details in certificates (like "Debian Etch" in the issuer) can be crucial hints in CTF challenges and real security assessments.

## Timeline

- **2006**: Debian developer accidentally removes entropy sources from OpenSSL
- **May 2008**: Vulnerability discovered and disclosed (CVE-2008-0166)
- **2008**: Security researchers generate and publish all ~32,767 possible weak keys
- **2026**: This CTF challenge exploits historical weak keys to decrypt TLS traffic

## References

- [CVE-2008-0166](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0166)
- [Debian Security Advisory DSA-1571-1](https://www.debian.org/security/2008/dsa-1571)
- [Weak Debian Keys Database](https://github.com/g0tmi1k/debian-ssh)
- [Analysis of the Debian OpenSSL Vulnerability](https://www.schneier.com/blog/archives/2008/05/random_number_b.html)

## Tools Used

- `tshark` - Network protocol analyzer
- `openssl` - SSL/TLS toolkit  
- `ssh-keygen` - SSH key manipulation
- `Python` - Custom script for key matching
- `git` - To clone weak keys repository

---

**Flag:** `HACKDAY{pRn9_1S_wE@K_AsF_no?}`  
**Message:** "PRNG is weak as f***, no?"
