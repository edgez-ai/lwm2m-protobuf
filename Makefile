################################################################################
# LwM2M Protobuf -> C (nanopb) build / generation Makefile
#
# Features:
#  - Downloads (clones) nanopb at the version you choose (default 0.4.9.1)
#  - Runs protoc with the nanopb plugin to generate .pb.c / .pb.h into generated/
#  - Provides clean + distclean targets
#  - Lets you override variables from the command line, e.g.:
#       make generate NANOPB_VERSION=0.4.9.1
#       make generate PROTOC=/path/to/protoc EXTRA_PROTO_PATHS="/usr/local/include"
#  - Keeps no generated files in git (add generated/ to .gitignore)
#
# Prereqs you must have installed (or available in PATH):
#  - git (for fetching nanopb)
#  - protoc (Protocol Buffers compiler)
#  - python3 (nanopb generator uses it)
#
# Optional: If you already have the nanopb plugin installed somewhere, you can
#           skip cloning by setting EXTERNAL_NANOPB_PLUGIN=/path/protoc-gen-nanopb
#           In that case the local nanopb sources are not required.
################################################################################

# ------------------------------------------------------------------------------
# Configurable variables (override on command line)
# ------------------------------------------------------------------------------
NANOPB_VERSION ?= 0.4.9.1
NANOPB_TAG ?= nanopb-$(NANOPB_VERSION)
NANOPB_DIR ?= build/nanopb-$(NANOPB_VERSION)
NANOPB_GIT_URL ?= https://github.com/nanopb/nanopb.git

# protoc binary (auto-detected from PATH if not provided)
PROTOC ?= protoc

# Extra include search paths for .proto imports (space separated)
# Provide a path that contains google/protobuf/timestamp.proto if it is not
# already found automatically by protoc on your system.
EXTRA_PROTO_PATHS ?=

# Output directories for generated source and header
SRC_DIR ?= src
INC_DIR ?= include
TMP_GEN_DIR ?= build/gen

# The .proto schema(s) for this module
PROTO_FILES := lwm2m.proto

# Allow user to supply an already-installed plugin binary
EXTERNAL_NANOPB_PLUGIN ?=

# Additional flags to pass to protoc's --nanopb_out (e.g. options file)
NANOPB_OUT_FLAGS ?=

# Quiet curl/wget logic could be added; relying on git clone here.

# ------------------------------------------------------------------------------
# Internal derived variables
# ------------------------------------------------------------------------------
INCLUDE_FLAGS := -I . -I $(NANOPB_DIR)/generator/proto $(addprefix -I,$(EXTRA_PROTO_PATHS))

ifeq ($(EXTERNAL_NANOPB_PLUGIN),)
  NANOPB_PLUGIN := $(NANOPB_DIR)/generator/protoc-gen-nanopb
else
  NANOPB_PLUGIN := $(EXTERNAL_NANOPB_PLUGIN)
endif

PROTO_BASENAMES := $(PROTO_FILES:%.proto=%)
GEN_C := $(addprefix $(SRC_DIR)/,$(addsuffix .pb.c,$(PROTO_BASENAMES)))
GEN_H := $(addprefix $(INC_DIR)/,$(addsuffix .pb.h,$(PROTO_BASENAMES)))
GEN_ALL := $(GEN_C) $(GEN_H)

.PHONY: all generate nanopb clean distclean print-vars help

all: generate

PY_OUT_DIR ?= python_out

help:
	@echo "Targets:"; \
	echo "  generate           - Fetch nanopb (if needed) and generate C code"; \
	echo "  generate-python    - Generate Python protobuf module(s) into $(PY_OUT_DIR)"; \
	echo "  nanopb             - Fetch/prepare nanopb only"; \
	echo "  clean              - Remove generated C sources"; \
	echo "  distclean          - Remove generated sources AND downloaded nanopb"; \
	echo "Variables (override like VAR=value):"; \
	echo "  NANOPB_VERSION, PROTOC, EXTRA_PROTO_PATHS, SRC_DIR, INC_DIR, PY_OUT_DIR"; \
	echo "  EXTERNAL_NANOPB_PLUGIN (skip cloning nanopb sources)"; \
	echo "Example:"; \
	echo "  make generate EXTRA_PROTO_PATHS=/opt/homebrew/Cellar/protobuf/25.1/include"; \
	echo "  make generate-python PY_OUT_DIR=python_out";

print-vars:
	@echo "NANOPB_VERSION=$(NANOPB_VERSION)"; \
	echo "NANOPB_DIR=$(NANOPB_DIR)"; \
	echo "PROTOC=$(PROTOC)"; \
	echo "NANOPB_PLUGIN=$(NANOPB_PLUGIN)"; \
	echo "EXTRA_PROTO_PATHS=$(EXTRA_PROTO_PATHS)"; \
	echo "SRC_DIR=$(SRC_DIR)"; \
	echo "INC_DIR=$(INC_DIR)"; \
	echo "PY_OUT_DIR=$(PY_OUT_DIR)"; \
	echo "PROTO_FILES=$(PROTO_FILES)";

# ------------------------------------------------------------------------------
# Fetch nanopb sources (only if we are not using an external plugin)
# ------------------------------------------------------------------------------
nanopb: $(if $(EXTERNAL_NANOPB_PLUGIN),,${NANOPB_DIR})

$(NANOPB_DIR):
ifeq ($(EXTERNAL_NANOPB_PLUGIN),)
	@echo "Cloning nanopb $(NANOPB_TAG) into $@";
	@mkdir -p $(dir $@)
	@if command -v git >/dev/null 2>&1; then \
		git clone --depth 1 --branch $(NANOPB_TAG) $(NANOPB_GIT_URL) $@ || { echo 'ERROR: git clone failed'; exit 1; }; \
	else \
		echo 'ERROR: git not found. Install git or set EXTERNAL_NANOPB_PLUGIN.'; exit 1; \
	fi
else
	@echo "Skipping clone (EXTERNAL_NANOPB_PLUGIN set)"
endif

# ------------------------------------------------------------------------------
# Code generation
# ------------------------------------------------------------------------------
generate: $(GEN_ALL)
	@echo "Generation complete: $(GEN_ALL)"

# ------------------------------------------------------------------------------
# Python code generation
# ------------------------------------------------------------------------------
.PHONY: generate-python
generate-python: $(addprefix $(PY_OUT_DIR)/,$(addsuffix _pb2.py,$(PROTO_BASENAMES)))
	@echo "Python generation complete: $^"

$(PY_OUT_DIR):
	@mkdir -p $@

$(PY_OUT_DIR)/%_pb2.py: %.proto | $(PY_OUT_DIR)
	@echo "Generating Python protobuf for $<"
	@if ! command -v $(PROTOC) >/dev/null 2>&1; then echo "ERROR: protoc not found (set PROTOC=)"; exit 1; fi
	$(PROTOC) --python_out=$(PY_OUT_DIR) $(INCLUDE_FLAGS) $<

$(SRC_DIR):
	@mkdir -p $@

$(INC_DIR):
	@mkdir -p $@

$(TMP_GEN_DIR):
	@mkdir -p $@

# Generate intermediate files (both .c and .h) into a temp dir
$(TMP_GEN_DIR)/%.pb.c $(TMP_GEN_DIR)/%.pb.h: %.proto | nanopb $(TMP_GEN_DIR)
	@echo "Generating nanopb sources for $<"
	@if ! command -v $(PROTOC) >/dev/null 2>&1; then echo "ERROR: protoc not found (set PROTOC=)"; exit 1; fi
	@if [ ! -x "$(NANOPB_PLUGIN)" ]; then \
		echo "Ensuring nanopb plugin executable"; \
		chmod +x $(NANOPB_PLUGIN) 2>/dev/null || true; \
	fi
	CMD="$(PROTOC) --plugin=protoc-gen-nanopb=$(NANOPB_PLUGIN) --nanopb_out=$(NANOPB_OUT_FLAGS):$(TMP_GEN_DIR) $(INCLUDE_FLAGS) $<"; \
	echo "Running: $$CMD"; \
	/bin/sh -c "$$CMD" || { \
		echo 'Falling back to direct python invocation of nanopb_generator'; \
		python3 $(NANOPB_DIR)/generator/nanopb_generator.py --output-dir=$(TMP_GEN_DIR) $< || exit 1; \
	}

# Copy from temp to final split locations
$(SRC_DIR)/%.pb.c: $(TMP_GEN_DIR)/%.pb.c | $(SRC_DIR)
	@cp $< $@

$(INC_DIR)/%.pb.h: $(TMP_GEN_DIR)/%.pb.h | $(INC_DIR)
	@cp $< $@

clean:
	@echo "Removing generated sources"
	rm -f $(GEN_C) $(GEN_H)
	rm -rf $(TMP_GEN_DIR)

distclean: clean
	@if [ -z "$(EXTERNAL_NANOPB_PLUGIN)" ]; then \
		echo "Removing cloned nanopb"; \
		rm -rf $(NANOPB_DIR); \
	else \
		echo "distclean: external plugin in use, leaving nanopb alone"; \
	fi

# Simple test-build: ensure generation only (compilation removed per request)
test-build: generate
	@echo "Generation successful (no object build)."

################################################################################
# End of Makefile
################################################################################
