#!/usr/bin/env python3
"""Helper script to build a FactoryPartition protobuf message and output base64.

Usage examples:
  python3 factory_partition_encode.py \
      --model 1 --vendor 100 --serial 12345678 \
      --public-key hex:001122... \
      --private-key file:device_private_key.bin \
      --bootstrap-server "https://bootstrap.example.com" \
      --signature file:signature.bin

Value formats:
  For all bytes fields you can provide one of:
    - raw string (will be UTF-8 encoded) e.g. "hello"
    - hex: prefixed hex string e.g. hex:deadbeef
    - base64: prefixed base64 string e.g. base64:YWJj
    - file: path to a file whose entire contents are used (binary safe) e.g. file:key.bin
"""
from __future__ import annotations
import argparse
import base64
import os
import sys
from pathlib import Path

# Add python_out to path if generated locally
SCRIPT_DIR = Path(__file__).parent
PY_OUT_DIR = SCRIPT_DIR / "python_out"
if PY_OUT_DIR.exists():
    sys.path.insert(0, str(PY_OUT_DIR))

try:
    import lwm2m_pb2  # type: ignore
except ImportError as e:
    print("ERROR: Unable to import generated 'lwm2m_pb2'. Run 'make generate-python' first.", file=sys.stderr)
    raise SystemExit(2)

BytesInput = str


def parse_bytes(value: BytesInput) -> bytes:
    if value.startswith("hex:"):
        return bytes.fromhex(value[4:])
    if value.startswith("base64:"):
        return base64.b64decode(value[7:])
    if value.startswith("file:"):
        path = Path(value[5:])
        return path.read_bytes()
    # plain string -> utf-8 bytes
    return value.encode("utf-8")


def build_factory_partition(args: argparse.Namespace) -> lwm2m_pb2.FactoryPartition:
    msg = lwm2m_pb2.FactoryPartition()
    msg.model = args.model
    msg.vendor = args.vendor
    msg.serial = args.serial
    if args.public_key is not None:
        msg.public_key = parse_bytes(args.public_key)
    if args.private_key is not None:
        msg.private_key = parse_bytes(args.private_key)
    if args.bootstrap_server is not None:
        # store as bytes (could be URL string); using UTF-8 encoding via parse
        msg.bootstrap_server = parse_bytes(args.bootstrap_server)
    if args.signature is not None:
        msg.signature = parse_bytes(args.signature)
    return msg


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Encode FactoryPartition message to base64")
    p.add_argument("--model", type=int, required=True, help="Model (fits in 8 bits per comment)")
    p.add_argument("--vendor", type=int, required=True, help="Vendor ID")
    p.add_argument("--serial", type=int, required=True, help="Serial number")
    p.add_argument("--public-key", dest="public_key", help="Public key bytes spec")
    p.add_argument("--private-key", dest="private_key", help="Private key bytes spec")
    p.add_argument("--bootstrap-server", dest="bootstrap_server", help="Bootstrap server (URL or bytes spec)")
    p.add_argument("--signature", dest="signature", help="Signature bytes spec")
    p.add_argument("--print-fields", action="store_true", help="Print a human friendly field summary before base64 output")
    p.add_argument("--out", type=Path, help="Optional file to write raw serialized bytes")

    args = p.parse_args(argv)

    msg = build_factory_partition(args)
    serialized = msg.SerializeToString()
    b64 = base64.b64encode(serialized).decode("ascii")

    if args.print_fields:
        print("FactoryPartition message:")
        # Use protobuf text format for clarity
        from google.protobuf import text_format  # type: ignore
        print(text_format.MessageToString(msg).strip())
        print("---")

    if args.out:
        args.out.write_bytes(serialized)
        print(f"Wrote raw serialized bytes to {args.out}")

    print(b64)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
