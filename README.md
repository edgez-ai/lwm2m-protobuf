# lwm2m-protobuf

Protobuf schema + nanopb C code generation for a constrained-device oriented
subset of LwM2M messaging.

## Contents

```
lwm2m.proto          Schema (edit this)
Makefile             Generation + convenience build
lwm2m_helpers.[ch]   Placeholder for future encode/decode helpers
generated/           (Created after you run make generate)
```

## Prerequisites

You need:

* `protoc` (Protocol Buffers compiler) in PATH
* `git` (to clone nanopb unless you provide your own plugin binary)
* `python3` (nanopb generator harness)
* A path where `google/protobuf/timestamp.proto` lives. If `protoc` is
	installed via Homebrew or your package manager it is usually bundled. If
	protoc cannot find the well-known types, add the include path via
	`EXTRA_PROTO_PATHS=/path/to/protobuf/include`.

## Quick Start

Generate nanopb C sources (defaults to version 0.4.9.1):

```bash
make generate
```

Outputs appear in `generated/lwm2m.pb.c` and `generated/lwm2m.pb.h`.

Sanity compile the generated code:

```bash
make test-build
```

Clean up:

```bash
make clean       # remove generated/
make distclean   # also remove cloned nanopb sources
```

## Overriding Variables

Example specifying protobuf include path (macOS Homebrew example) and a custom
nanopb version:

```bash
make generate EXTRA_PROTO_PATHS=/opt/homebrew/Cellar/protobuf/25.1/include NANOPB_VERSION=0.4.9.1
```

Using an already installed nanopb plugin (skips clone):

```bash
make generate EXTERNAL_NANOPB_PLUGIN=$(which protoc-gen-nanopb)
```

List internal variables:

```bash
make print-vars
```

## Integrating into Another Build (ESP-IDF, CMake, etc.)

1. Add `generated/` to your compiler's include paths.
2. Compile `generated/lwm2m.pb.c` along with your sources.
3. Include `lwm2m.pb.h` where you need the message structs.

For ESP-IDF you can copy or symlink this directory into a component, or just
add the generated sources to an existing component's `CMakeLists.txt`.

## Regeneration Strategy

Regenerate whenever you change `lwm2m.proto`:

```bash
make clean generate
```

Commit the schema + Makefile, but generally omit the generated `.pb.*` unless
you need to distribute pre-generated code (CI reproducibility, language users
without protoc, etc.).

## Python Bindings & FactoryPartition Encoding

If you want to experiment with the messages (especially `FactoryPartition`) in
Python, a helper target and script are included.

### 1. Generate Python protobuf module

```bash
make generate-python            # creates python_out/lwm2m_pb2.py
```

Override the output directory if desired:

```bash
make generate-python PY_OUT_DIR=my_python_pb
```

### 2. Encode a FactoryPartition message to Base64

Use the helper script `factory_partition_encode.py` (it auto-adds `python_out/`
to `PYTHONPATH` if present):

```bash
python3 factory_partition_encode.py \
	--model 1 \
	--vendor 42 \
	--serial 1001 \
	--public-key hex:00112233aabbccddeeff \
	--private-key hex:ffeeddccbbaa33221100 \
	--bootstrap-server https://bootstrap.example.com \
	--signature hex:deadbeef \
	--print-fields
```

This prints a human‑readable text form (when `--print-fields` is used) followed
by the Base64 of the serialized protobuf.

Optionally write raw bytes:

```bash
python3 factory_partition_encode.py ... --out factory_partition.bin
```

### 3. Bytes field input formats

For any bytes argument (`--public-key`, `--private-key`, `--bootstrap-server`,
`--signature`) you can supply one of:

* `plainstring` (UTF‑8 encoded directly)
* `hex:deadbeef` (hex string after `hex:`)
* `base64:YWJj` (Base64 after `base64:`)
* `file:path/to/file.bin` (binary file contents)

### 4. Decoding (optional)

To decode later (ad‑hoc):

```bash
python3 - <<'PY'
import base64, sys, pathlib
from google.protobuf import json_format
sys.path.insert(0, 'python_out')  # adjust if you changed PY_OUT_DIR
import lwm2m_pb2
b64 = sys.argv[1] if len(sys.argv) > 1 else input('Base64> ').strip()
msg = lwm2m_pb2.FactoryPartition()
msg.ParseFromString(base64.b64decode(b64))
print(msg)
print('JSON:')
print(json_format.MessageToJson(msg))
PY
```

### 5. Version warning note

If you see a protobuf runtime/codegen version mismatch warning, update your
`protoc` to a version closer to the installed Python `protobuf` package, or
upgrade the Python package:

```bash
python3 -m pip install --upgrade protobuf
```

The current script still works despite the warning; address it proactively for
future compatibility.

## Cryptographic Functions

This library now includes ECDH (Elliptic Curve Diffie-Hellman) AES key derivation functions for secure LwM2M device communication.

### ECDH AES Key Derivation

Two functions are provided for deriving AES-256 keys from ECDH shared secrets:

#### Simple Key Derivation

```c
#include "lwm2m_helpers.h"

uint8_t peer_public_key[65];  // 0x04 + 32-byte X + 32-byte Y (uncompressed P-256)
uint8_t our_private_key[32];  // 32-byte private key for P-256
uint8_t derived_aes_key[32];  // Output: 256-bit AES key

int result = lwm2m_ecdh_derive_aes_key_simple(peer_public_key, our_private_key, derived_aes_key);
if (result == 0) {
    // Use derived_aes_key for AES-256-GCM encryption/decryption
    printf("Key derivation successful!\n");
} else {
    printf("Key derivation failed with code: %d\n", result);
}
```

#### Advanced Key Derivation with Salt and Info

```c
const char *salt = "my-application-salt";
const char *info = "LwM2M-Device-Key";

int result = lwm2m_ecdh_derive_aes_key(peer_public_key, our_private_key, derived_aes_key,
                                      (const uint8_t *)salt, strlen(salt),
                                      (const uint8_t *)info, strlen(info));
```

### Requirements

- **ESP-IDF**: Uses built-in mbedTLS library (automatically included)
- **Other platforms**: Requires linking against mbedTLS

### Error Codes

- `0`: Success
- `-1`: Invalid arguments (NULL pointers)
- `-2`: ECDH computation failure
- `-3`: HKDF derivation failure

### Security Notes

- Uses NIST P-256 (secp256r1) elliptic curve
- HKDF-SHA256 for key derivation from shared secret
- Properly clears sensitive data from memory
- Thread-safe implementation

### ChaCha20-Poly1305 AEAD Encryption

The library now includes ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD) functions for secure message encryption.

#### Basic Usage

```c
#include "lwm2m_helpers.h"

// Use a derived key from ECDH or your own 32-byte key
uint8_t key[32];         // 256-bit encryption key
uint8_t nonce[12];       // 96-bit nonce (must be unique per encryption)
uint8_t tag[16];         // 128-bit authentication tag
uint8_t ciphertext[256];
uint8_t plaintext[256];

const char *message = "Secret message to encrypt";
const char *aad = "Public authenticated data";

// Generate a secure random nonce
int result = lwm2m_chacha20_generate_nonce(nonce);
if (result != 0) {
    printf("Nonce generation failed: %d\n", result);
    return -1;
}

// Encrypt
result = lwm2m_chacha20_poly1305_encrypt(key, nonce,
                                        (uint8_t *)message, strlen(message),
                                        (uint8_t *)aad, strlen(aad),
                                        ciphertext, tag);
if (result == 0) {
    printf("Encryption successful!\n");
    // Transmit: nonce + ciphertext + tag (aad can be sent separately)
}

// Decrypt
result = lwm2m_chacha20_poly1305_decrypt(key, nonce,
                                        ciphertext, strlen(message),
                                        (uint8_t *)aad, strlen(aad),
                                        tag, plaintext);
if (result == 0) {
    plaintext[strlen(message)] = '\0';  // null-terminate for string
    printf("Decrypted: %s\n", (char *)plaintext);
} else if (result == -3) {
    printf("Authentication failed - message was tampered with!\n");
}
```

#### Testing ChaCha20-Poly1305

A test program is included to demonstrate the functionality:

```bash
make test-chacha20
./test_chacha20  # Run the demonstration (ESP-IDF or mbedTLS required)
```

#### ChaCha20-Poly1305 Error Codes

- `0`: Success
- `-1`: Invalid arguments (NULL pointers, invalid lengths)
- `-2`: Encryption/decryption failure  
- `-3`: Authentication failure (tag verification failed during decryption)

#### ChaCha20-Poly1305 Security Notes

- Uses ChaCha20 stream cipher with Poly1305 authenticator
- 256-bit keys, 96-bit nonces, 128-bit authentication tags
- Nonces must be unique for each encryption with the same key
- Provides both confidentiality and authenticity
- Constant-time tag verification prevents timing attacks
- Automatically clears sensitive intermediate values

#### Integration with ECDH

ChaCha20-Poly1305 works perfectly with ECDH-derived keys:

```c
// First derive a shared key using ECDH
uint8_t shared_key[32];
lwm2m_ecdh_derive_aes_key_simple(peer_public_key, our_private_key, shared_key);

// Then use it for ChaCha20-Poly1305 encryption
uint8_t nonce[12], tag[16], ciphertext[256];
lwm2m_chacha20_generate_nonce(nonce);
lwm2m_chacha20_poly1305_encrypt(shared_key, nonce, plaintext, plaintext_len, 
                                aad, aad_len, ciphertext, tag);
```

## Future Enhancements

* Add nanopb options file to fine-tune field allocation / max sizes.
* ✅ ~~Provide helper encode/decode functions in `lwm2m_helpers.c`.~~ (Added ECDH AES key derivation and ChaCha20-Poly1305)
* Create a CMakeLists.txt wrapper (if desired by consuming projects).
* ✅ ~~Add ChaCha20-Poly1305 encryption~~ (Added with nonce generation)
* Add digital signature functions (ECDSA, EdDSA)
* Add unit tests for cryptographic functions
* Add AES-GCM encryption as an alternative to ChaCha20-Poly1305

---
MIT or the license you prefer for your schema/code (adjust as necessary).

