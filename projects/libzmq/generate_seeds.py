#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Generate binary seed corpora for the in-process libzmq decoder harnesses.

Seeds represent minimal valid protocol frames to give libFuzzer an initial
corpus that exercises each decoder state machine branch from the first run.
Called from build.sh after ci_build.sh so it runs inside the oss-fuzz
Docker container.

Usage: python3 generate_seeds.py <output_base_dir>
  output_base_dir/test_zmtp_decode_fuzzer/       -- ZMTP v2/v3 frame seeds
  output_base_dir/test_zmtp_v1_decode_fuzzer/    -- ZMTP v1 frame seeds
  output_base_dir/test_ws_decode_fuzzer/         -- WebSocket unmasked seeds
  output_base_dir/test_ws_decode_masked_fuzzer/  -- WebSocket masked seeds
"""

import os
import struct
import sys


def write_seed(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def generate_zmtp_seeds(base: str) -> None:
    """ZMTP v2/v3 frames: [flags(1)] [size(1 or 8)] [payload...]
    flags: 0x00=none, 0x01=more, 0x02=large(8-byte size), 0x04=command
    If large_flag: size is big-endian 64-bit; else 8-bit.
    """
    d = os.path.join(base, "test_zmtp_decode_fuzzer")

    # No flags, zero-length message
    write_seed(f"{d}/01_empty_message", bytes([0x00, 0x00]))

    # No flags, one-byte payload 'A'
    write_seed(f"{d}/02_one_byte_msg", bytes([0x00, 0x01, 0x41]))

    # more_flag=1, one-byte payload 'B'
    write_seed(f"{d}/03_more_flag", bytes([0x01, 0x01, 0x42]))

    # command_flag=4, three-byte payload 'ABC'
    write_seed(f"{d}/04_command_flag", bytes([0x04, 0x03, 0x41, 0x42, 0x43]))

    # large_flag=2, 8-byte big-endian size=0
    write_seed(f"{d}/05_large_zero", bytes([0x02]) + struct.pack(">Q", 0))

    # large_flag=2, 8-byte big-endian size=1, payload 'X'
    write_seed(f"{d}/06_large_one", bytes([0x02]) + struct.pack(">Q", 1) + b"X")

    # Two concatenated messages: A and B (exercises decode loop)
    write_seed(f"{d}/07_multi_msg", bytes([0x00, 0x01, 0x41, 0x00, 0x01, 0x42]))


def generate_zmtp_v1_seeds(base: str) -> None:
    """ZMTP v1 frames: [size(1)] [flags(1)] [payload: size-1 bytes]
    size 1-254: payload_length = size; message_body = size - 1 bytes (+ 1 flags byte)
    size 0xFF: read 8-byte big-endian length, then flags + body.
    size 0: EPROTO error.
    flags: only bit 0 (more) is used in v1.
    """
    d = os.path.join(base, "test_zmtp_v1_decode_fuzzer")

    # size=1: flags-only, zero-byte body (flags=0x00, no more flag)
    write_seed(f"{d}/01_empty_body", bytes([0x01, 0x00]))

    # size=2: flags=0, one-byte body 'A'
    write_seed(f"{d}/02_one_byte_msg", bytes([0x02, 0x00, 0x41]))

    # size=2: flags=more(0x01), one-byte body 'B'
    write_seed(f"{d}/03_more_flag", bytes([0x02, 0x01, 0x42]))

    # size=4: flags=0, three-byte body 'ABC'
    write_seed(f"{d}/04_multi_byte_body", bytes([0x04, 0x00, 0x41, 0x42, 0x43]))

    # 8-byte length, size=2 (1-byte body): 0xFF + BE64(2) + flags + body
    write_seed(
        f"{d}/05_large_one_byte",
        bytes([0xFF]) + struct.pack(">Q", 2) + bytes([0x00, 0x58]),
    )

    # 8-byte length, size=1 (0-byte body): 0xFF + BE64(1) + flags
    write_seed(
        f"{d}/06_large_zero_body",
        bytes([0xFF]) + struct.pack(">Q", 1) + bytes([0x00]),
    )

    # Two concatenated short messages: 'A' and 'B'
    write_seed(
        f"{d}/07_multi_msg",
        bytes([0x02, 0x00, 0x41, 0x02, 0x00, 0x42]),
    )


def generate_ws_unmasked_seeds(base: str) -> None:
    """WebSocket frames (unmasked, server-to-server): RFC 6455 framing.
    Byte 0: FIN(0x80) | opcode; Byte 1: [MASK(0x80)] | payload_len
    Binary opcode=0x02, close=0x08, ping=0x09, pong=0x0A
    ZMQ flags byte is the first byte of the binary frame payload.
    """
    d = os.path.join(base, "test_ws_decode_fuzzer")

    # FIN+binary, length=1, ZMQ_flags=0 (no flags, empty ZMQ message)
    write_seed(f"{d}/01_binary_empty", bytes([0x82, 0x01, 0x00]))

    # FIN+binary, length=2, ZMQ_flags=0, payload='A'
    write_seed(f"{d}/02_binary_one_byte", bytes([0x82, 0x02, 0x00, 0x41]))

    # FIN+binary, length=2, ZMQ_flags=more(0x01), payload='B'
    write_seed(f"{d}/03_binary_more_flag", bytes([0x82, 0x02, 0x01, 0x42]))

    # Close frame (opcode=0x08), zero-length
    write_seed(f"{d}/04_close", bytes([0x88, 0x00]))

    # Ping frame (opcode=0x09), zero-length
    write_seed(f"{d}/05_ping", bytes([0x89, 0x00]))

    # Pong frame (opcode=0x0A), zero-length
    write_seed(f"{d}/06_pong", bytes([0x8A, 0x00]))

    # 2-byte length form (payload_len=126): length=127 bytes total payload
    # Byte 1=0x7E means next 2 bytes are 16-bit length
    payload_len = 127
    frame = bytes([0x82, 0x7E]) + struct.pack(">H", payload_len) + bytes(payload_len)
    write_seed(f"{d}/07_medium_frame", frame)


def generate_ws_masked_seeds(base: str) -> None:
    """WebSocket frames (masked, client-to-server): RFC 6455 framing.
    Byte 1 has MASK bit set (0x80); followed by 4-byte masking key;
    payload XORed with masking key cyclically.
    Masking key 0x11223344 used throughout.
    """
    d = os.path.join(base, "test_ws_decode_masked_fuzzer")
    mask = bytes([0x11, 0x22, 0x33, 0x44])

    def masked(payload: bytes) -> bytes:
        return bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

    # FIN+binary, MASK, length=1, ZMQ_flags=0 masked with key
    zmq_flags = bytes([0x00])
    write_seed(
        f"{d}/01_binary_empty",
        bytes([0x82, 0x80 | 1]) + mask + masked(zmq_flags),
    )

    # FIN+binary, MASK, length=2, ZMQ_flags=0, payload='A' masked
    payload = bytes([0x00, 0x41])
    write_seed(
        f"{d}/02_binary_one_byte",
        bytes([0x82, 0x80 | 2]) + mask + masked(payload),
    )

    # Close frame, MASK, zero-length (mask present, no payload to unmask)
    write_seed(f"{d}/03_close", bytes([0x88, 0x80]) + mask)

    # Ping frame, MASK, zero-length
    write_seed(f"{d}/04_ping", bytes([0x89, 0x80]) + mask)


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <output_base_dir>", file=sys.stderr)
        sys.exit(1)
    base = sys.argv[1]
    generate_zmtp_seeds(base)
    generate_zmtp_v1_seeds(base)
    generate_ws_unmasked_seeds(base)
    generate_ws_masked_seeds(base)
    print(f"Seeds written to {base}")


if __name__ == "__main__":
    main()
