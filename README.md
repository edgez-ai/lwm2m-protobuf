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

## Future Enhancements

* Add nanopb options file to fine-tune field allocation / max sizes.
* Provide helper encode/decode functions in `lwm2m_helpers.c`.
* Create a CMakeLists.txt wrapper (if desired by consuming projects).

---
MIT or the license you prefer for your schema/code (adjust as necessary).

