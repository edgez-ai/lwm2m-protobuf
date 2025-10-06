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

## Future Enhancements

* Add nanopb options file to fine-tune field allocation / max sizes.
* Provide helper encode/decode functions in `lwm2m_helpers.c`.
* Create a CMakeLists.txt wrapper (if desired by consuming projects).

---
MIT or the license you prefer for your schema/code (adjust as necessary).

