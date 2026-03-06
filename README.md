# dtls-schc

RFC 8724-aligned SCHC header compression layered over DTLS 1.2, integrated via WolfSSL custom I/O callbacks. Built as part of a CRIME-style side-channel threat analysis for DTLS-over-SCHC.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [SCHC Rule Design](#schc-rule-design)
- [Prerequisites](#prerequisites)
- [Building](#building)
- [Running](#running)
- [Running Tests](#running-tests)
- [How It Works](#how-it-works)
- [Side-Channel Observations](#side-channel-observations)
- [Known Limitations](#known-limitations)
- [Project Structure](#project-structure)

---

## Overview

This project implements a minimal SCHC (Static Context Header Compression) compressor — `schc-mini` — that compresses DTLS 1.2 record headers before transmission and decompresses them on receipt. The compression is injected at the WolfSSL custom I/O layer, meaning Wireshark and any network observer sees only the compressed SCHC packet as the UDP payload, never the raw DTLS record header.

The project was built to investigate whether SCHC header compression over DTLS introduces a CRIME-style side-channel: an observer that can see compressed packet sizes and rule IDs can infer protocol state (handshake vs. application data), content type, epoch, and sequence number — without breaking encryption.

**Why DTLS 1.2 and not 1.3?**

DTLS 1.3 already encrypts the content type and uses a compact unified header after the key exchange phase, partially mitigating the side-channel by design. DTLS 1.2 has fully plaintext headers — making it the better target for demonstrating what SCHC leaks.

---

## Architecture

```text
┌───────────────────────────────────────┐
│            Application                │
│     wolfSSL_write / wolfSSL_read      │
└───────────────┬───────────────────────┘
                │
┌───────────────▼───────────────────────┐
│         WolfSSL DTLS 1.2              │
│   Constructs full 13-byte DTLS record │
└───────────────┬───────────────────────┘
                │  Custom I/O callback intercepts here
┌───────────────▼───────────────────────┐
│           schc-mini                   │
│  send: schc_compress()                │
│  recv: schc_decompress()              │
│                                       │
│  Wire format:                         │
│  [ RuleID (1B) | Residue | Payload ]  │
└───────────────┬───────────────────────┘
                │
┌───────────────▼───────────────────────┐
│           UDP Socket                  │
│  Observer sees compressed packet only │
└───────────────────────────────────────┘
```

The WolfSSL custom I/O callbacks (`wolfSSL_CTX_SetIOSend` / `wolfSSL_CTX_SetIORecv`) give access to the fully constructed DTLS record just before it hits the UDP socket. This is the hook point where `schc_compress` and `schc_decompress` are called.

---

## SCHC Rule Design

The rule context (`schc-mini/schc_mini.c`) defines 4 rules targeting DTLS 1.2's fixed 13-byte header:

```text
Byte offsets:
[0]     Content Type  (1 byte)
[1-2]   Version       (2 bytes)  0xFEFD = DTLS 1.2
[3-4]   Epoch         (2 bytes)
[5-10]  Sequence Num  (6 bytes)
[11-12] Length        (2 bytes)
```

| Rule   | Target                    | Fields Elided             | Residue Size                     | Compression Delta |
| ------ | ------------------------- | ------------------------- | -------------------------------- | ----------------- |
| Rule 1 | Handshake, Epoch=0, Seq=0 | Type, Version, Epoch, Seq | 2 bytes (Length only)            | −10 bytes         |
| Rule 2 | Handshake, Epoch=0, Seq=1 | Type, Version, Epoch, Seq | 2 bytes (Length only)            | −10 bytes         |
| Rule 3 | Handshake, Epoch=1, Seq=0 | Type, Version, Epoch, Seq | 2 bytes (Length only)            | −10 bytes         |
| Rule 4 | Catch-all (type ≠ 22)     | Version only              | 11 bytes (Type+Epoch+Seq+Length) | −2 bytes          |

**Matching Operators (MO):**

- `MO_EQUAL` — field must equal the Target Value (TV); matched fields are elided
- `MO_IGNORE` — field always passes; sent as residue (`VALUE_SENT`)

**Compression/Decompression Actions (CDA):**

- `NOT_SENT` — field elided; reconstructed from TV on decompression
- `VALUE_SENT` — field transmitted verbatim in the compression residue

Rules are evaluated in order (Rule 1 → Rule 4). The first match wins.

---

## Prerequisites

- **CMake** ≥ 3.20
- **WolfSSL** 5.8.4 (adjust path in `CMakeLists.txt` if different)
- **C11** compatible compiler (clang or gcc)
- **OpenSSL** or self-signed certs for the server (PEM format)

### Install WolfSSL (macOS via Homebrew)

```bash
brew install wolfssl
```

For other platforms, build from source:

```bash
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-dtls
make
sudo make install
```

### Generate Server Certificates

The server requires `certs/server-cert.pem` and `certs/server-key.pem` relative to the build directory (i.e., `../certs/` from `build/`):

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -keyout certs/server-key.pem \
  -out certs/server-cert.pem -days 365 -nodes \
  -subj "/CN=localhost"
```

---

## Building

```bash
git clone https://github.com/hashedalgorithm/dtls-schc.git
cd dtls-schc
mkdir build && cd build
cmake ..
make
```

This produces three executables in `build/`:

| Binary   | Description                              |
| -------- | ---------------------------------------- |
| `server` | DTLS 1.2 server with SCHC compression    |
| `client` | DTLS 1.2 client with SCHC compression    |
| `test`   | Controlled header compression experiment |

### Adjusting the WolfSSL Path

If WolfSSL is not installed at `/opt/homebrew/Cellar/wolfssl/5.8.4`, edit `CMakeLists.txt`:

```cmake
set(WOLFSSL_PREFIX /your/wolfssl/install/path)
```

---

## Running

Open two terminals from the `build/` directory.

**Terminal 1 — Server:**

```bash
./server
```

Expected output:

```text
UDP Server listening on port 11111
Waiting for client...
```

**Terminal 2 — Client:**

```bash
./client
```

Expected output:

```text
dtls_mini_compress 235 bytes
dtls_mini_decompress 60 bytes
...
Handshake complete!. Sending message...
dtls_mini_compress 59 bytes
Sent: "Hello from DTLS client!"
Closing connection and exiting.
```

Server output after a successful session:

```text
Client connected from 127.0.0.1
dtls_mini_decompress 245 bytes
dtls_mini_compress 50 bytes
...
Handshake complete. Reading message...
dtls_mini_decompress 60 bytes
Received: "Hello from DTLS client!"
Session closed, returning to idle
```

### Enabling Debug Prints

Uncomment the `print_dtls_record` calls in `client.c` and `server.c` to see full hex dumps of each DTLS record before and after compression:

```c
// In send_dtls_record():
print_dtls_record(SEND_DTLS_RECORD, buffer, size);
print_dtls_record(SEND_DTLS_RECORD, (char *)result_buffer, out_len);
```

### Capturing with Wireshark

The compressed SCHC packets are visible as raw UDP payloads (port 11111) on the loopback interface. WolfSSL's DTLS dissector will not recognise them since the header is compressed.

```bash
# Filter in Wireshark:
udp.port == 11111
```

---

## Running Tests

The `test` binary runs a controlled compression experiment across 12 sections covering the full DTLS 1.2 message lifecycle using synthetic headers:

```bash
./test
```

Sample output:

```text
=== DTLS RECORD HEADER SCHC COMPRESSION EXPERIMENT ===

--- [1] NORMAL HANDSHAKE FLOW (DTLS 1.2 / 0xFEFD) ---
1.01 ClientHello (handshake, epoch=0, seq=0)        | rule=Rule-1 | in= 33 | out= 23 | diff=-10
1.02 HelloVerifyRequest (handshake, epoch=0, seq=0) | rule=Rule-1 | in= 33 | out= 23 | diff=-10
1.03 ClientHello+Cookie (handshake, epoch=0, seq=1) | rule=Rule-2 | in= 33 | out= 23 | diff=-10
...
1.13 ApplicationData (appdata, epoch=1, seq=1)      | rule=Rule-4 | in= 33 | out= 32 | diff=-1

--- [2] RETRANSMISSION SCENARIOS ---
...
--- [7] VERSION FIELD VARIANTS ---
7.02 DTLS 1.0 (0xFEFF) - legacy                    | rule=Rule-4 | in= 33 | out= 32 | diff=-1
...
=== EXPERIMENT COMPLETE ===
```

Test sections:

| Section | Coverage                                            |
| ------- | --------------------------------------------------- |
| 1       | Normal DTLS 1.2 handshake flow                      |
| 2       | Retransmission scenarios                            |
| 3       | Alert messages (all types, both epochs)             |
| 4       | ChangeCipherSpec variants                           |
| 5       | Epoch progression                                   |
| 6       | Sequence number edge cases (0, max, near-rollover)  |
| 7       | Version field variants (DTLS 1.0, TLS 1.2, unknown) |
| 8       | Content type variants (20–24, 0x00, 0xFF)           |
| 9       | Strict rule boundary conditions                     |
| 10      | Renegotiation flow                                  |
| 11      | Session resumption                                  |
| 12      | Error and malformed scenarios                       |

> **Note:** The test binary uses a fixed 20-byte dummy payload (`0xAB, 0x00...`), so `in` is always 33 bytes (13-byte header + 20-byte payload). The compression is applied to the header only; payload passes through untouched.

---

## How It Works

### Compression (`schc_compress`)

1. Parse the incoming DTLS record buffer (first 13 bytes = header, remainder = payload).
2. Walk the rule context in order; for each rule, check all `MO_EQUAL` fields against the header — if all match, the rule is selected.
3. Write `RuleID` (1 byte) to the output buffer.
4. For each `VALUE_SENT` field in the matched rule, copy the raw bytes from the header into the residue.
5. Append the payload verbatim.
6. Return the total compressed length.

### Decompression (`schc_decompress`)

1. Read the first byte as `RuleID`; look up the rule by ID.
2. Calculate expected residue size (sum of `fl` for all `VALUE_SENT` fields).
3. Reconstruct the 13-byte header:
   - `NOT_SENT` fields → write the Target Value from the rule.
   - `VALUE_SENT` fields → read bytes sequentially from the residue stream.
4. Copy reconstructed header + remaining payload to the output buffer.
5. Return the decompressed total length.

### Wire Format

```text
[ RuleID : 1 byte ] [ Residue : variable ] [ Payload : variable ]

Rule 1/2/3 residue: [ Length (2 bytes) ]           → 3 bytes total overhead
Rule 4 residue:     [ Type(1) Epoch(2) Seq(6) Len(2) ] → 12 bytes total overhead
```

---

## Side-Channel Observations

From live Wireshark captures and the controlled test:

| Packet | Role                  | Rule   | Compressed Size | Delta |
| ------ | --------------------- | ------ | --------------- | ----- |
| 907    | ClientHello           | Rule-1 | 235 bytes       | −10   |
| 908    | HelloVerifyRequest    | Rule-1 | 50 bytes        | −10   |
| 909    | ClientHello+Cookie    | Rule-2 | 267 bytes       | −10   |
| 910    | ServerHello+Cert      | Rule-2 | 1268 bytes      | −10   |
| 911    | ClientKeyExchange+CCS | Rule-3 | 165 bytes       | −10   |
| 912    | CCS+Finished          | Rule-3 | 74 bytes        | −10   |
| 913    | Finished              | Rule-4 | 59 bytes        | −2    |
| 914    | Application Data      | Rule-4 | 38 bytes        | −2    |

**What an observer can infer:**

- The `RuleID` is the first byte of every UDP payload — transmitted in plaintext.
- A jump from Rule 1/2/3 (−10 bytes) to Rule 4 (−2 bytes) precisely marks the handshake→application-data transition.
- By correlating RuleID frequency and packet timing across multiple sessions, an observer can predict `content_type`, `epoch`, and `sequence_number` without breaking encryption.
- This is analogous to CRIME but applies to protocol-state metadata rather than secret content — the leak is deterministic and structural, not probabilistic.

**CRIME vs. SCHC Side-Channel:**

| Aspect               | CRIME                          | SCHC Side-Channel                                |
| -------------------- | ------------------------------ | ------------------------------------------------ |
| Type                 | Active attack                  | Passive observation                              |
| Target               | TLS/HTTPS secrets              | Protocol state metadata                          |
| Compression          | Dynamic (DEFLATE)              | Static rule-based                                |
| Attacker requirement | MitM + victim-controlled input | Passive observer only                            |
| Mitigation           | Disable compression            | Padding / rule consolidation / header encryption |

---

## Known Limitations

**Rule granularity leaks state.** Each rule maps to a distinct handshake phase. The more rules, the more state an observer can fingerprint. A single catch-all rule would eliminate this, at the cost of compression efficiency.

**RuleID is plaintext.** The first byte of every compressed packet unambiguously identifies the protocol phase. Encrypting the RuleID with the handshake key would mitigate this but is only possible after key derivation.

**DTLS 1.3 incompatibility.** After the key exchange, DTLS 1.3 switches from the DTLS 1.2-compatible 13-byte header to a compact variable-length unified header. The fixed-offset rule logic in `schc_mini.c` breaks at this point — `schc_compress` returns `-1` and the connection drops. Supporting DTLS 1.3 requires:

- Detection of the unified header format (first byte MSB flags).
- Separate rule sets and offset logic for the compact header.

**No fragment reassembly.** WolfSSL may fragment large handshake messages across multiple DTLS records. Each record is compressed independently; the compressor has no reassembly context.

**Fixed payload size in tests.** The test binary uses a 20-byte static dummy payload. Real sessions have variable-length payloads that dominate total packet size, making the header delta relatively smaller.

---

## Project Structure

```text
.
├── CMakeLists.txt          # Build configuration
├── client.c                # DTLS client with SCHC I/O callbacks
├── server.c                # DTLS server with SCHC I/O callbacks
├── schc-mini/
│   ├── schc_mini.h         # Public API, types, rule IDs, field descriptors
│   └── schc_mini.c         # Rule context, compress/decompress implementation
├── test/
│   └── test.c              # Controlled header compression experiment (12 sections)
└── certs/                  # Server certificate and key (not committed — generate locally)
    ├── server-cert.pem
    └── server-key.pem
```

---

## Attachments

- Wireshark capture: [Google Drive](https://drive.google.com/file/d/1eZw6JZq1H__LiUoV5UIVsGtO7ENqT112/view?usp=drive_link)

---

## References

1. RFC 9147 — DTLS 1.3: https://datatracker.ietf.org/doc/html/rfc9147
2. RFC 6347 — DTLS 1.2: https://datatracker.ietf.org/doc/html/rfc6347
3. RFC 8724 — SCHC: https://datatracker.ietf.org/doc/rfc8724/
4. RFC 8446 — TLS 1.3: https://datatracker.ietf.org/doc/html/rfc8446
5. CVE-2012-4929 — CRIME: https://nvd.nist.gov/vuln/detail/cve-2012-4929
6. WolfSSL: https://github.com/wolfSSL/wolfssl
7. libschc: https://github.com/imec-idlab/libschc
