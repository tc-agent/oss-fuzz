#!/usr/bin/env python3
# Copyright 2021 Google LLC
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
################################################################################
"""Build seed corpora for the GPAC oss-fuzz harnesses.

The broad ``fuzz_probe_analyze`` harness (which feeds an arbitrary file into a
full GPAC filter session) ships with no seed corpus, so it must rediscover
every container/codec magic from scratch. This script assembles a seed corpus
by (1) synthesising small, probe-valid files for ~35 formats GPAC supports and
(2) reusing the real media samples already present in the gpac testsuite
checkout. No binary blobs are committed to oss-fuzz: everything is generated or
sourced from the testsuite submodule at build time.

Usage: gen_fuzz_seeds.py <testsuite_dir> <out_dir>
  <testsuite_dir>  gpac testsuite checkout (contains media/ and oss-fuzzers/)
  <out_dir>        directory to write <harness>_seed_corpus.zip files into
"""
import os
import struct
import sys
import zipfile


# --------------------------------------------------------------------------
# synthetic format generators
# --------------------------------------------------------------------------
def _riff(form, chunks):
    body = form + b"".join(chunks)
    return b"RIFF" + struct.pack("<I", len(body)) + body


def _chunk(cid, data):
    d = data + (b"\x00" if len(data) % 2 else b"")
    return cid + struct.pack("<I", len(data)) + d


def _ogg_page(serial, seq, granule, packets, hdr_type=0):
    segs, body = [], b""
    for p in packets:
        n = len(p)
        while n >= 255:
            segs.append(255)
            n -= 255
        segs.append(n)
        body += p
    return (b"OggS" + bytes([0, hdr_type]) + struct.pack("<q", granule) +
            struct.pack("<III", serial, seq, 0) + bytes([len(segs)]) +
            bytes(segs) + body)


def _ebml_id(v):
    for n in (1, 2, 3, 4):
        if v < (1 << (8 * n)):
            return v.to_bytes(n, "big")
    return v.to_bytes(4, "big")


def _ebml_size(n):
    if n < 0x7F:
        return bytes([0x80 | n])
    if n < 0x3FFF:
        return struct.pack(">H", 0x4000 | n)
    if n < 0x1FFFFF:
        return (0x200000 | n).to_bytes(3, "big")
    return struct.pack(">I", 0x10000000 | n)


def _el(eid, data):
    return _ebml_id(eid) + _ebml_size(len(data)) + data


def _el_u(eid, val):
    d = b"\x00" if val == 0 else val.to_bytes((val.bit_length() + 7) // 8, "big")
    return _el(eid, d)


def _el_s(eid, s):
    return _el(eid, s.encode())


def _el_f(eid, val):
    return _el(eid, struct.pack(">d", val))


def _ts_packet(pid, payload, pusi=1, cc=0):
    hdr = 0x47000000 | ((pusi & 1) << 22) | ((pid & 0x1FFF) << 8)
    hdr |= (1 << 4) | (cc & 0xF)
    pkt = struct.pack(">I", hdr) + (b"\x00" if pusi else b"") + payload
    return pkt + b"\xff" * (188 - len(pkt))


def _adts(payload_len):
    flen = 7 + payload_len
    h = bytearray(7)
    h[0], h[1] = 0xFF, 0xF1
    h[2] = (1 << 6) | (4 << 2)
    h[3] = (2 << 6) | (flen >> 11)
    h[4] = (flen >> 3) & 0xFF
    h[5] = ((flen & 7) << 5) | 0x1F
    h[6] = 0xFC
    return bytes(h) + b"\x00" * payload_len


# --------- ISOBMFF ----------
_MATRIX = struct.pack(">9I", 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000)


def _box(t, payload):
    return struct.pack(">I", 8 + len(payload)) + t + payload


def _fbox(t, version, flags, payload):
    return _box(t, struct.pack(">I", (version << 24) | flags) + payload)


def _mp4(fragmented=False):
    ftyp = _box(b"ftyp", b"isom" + struct.pack(">I", 0x200) +
                b"isom" + b"iso2" + b"avc1" + b"mp41")

    def mvhd(next_id):
        p = struct.pack(">IIII", 0, 0, 1000, 2000)
        p += struct.pack(">I", 0x10000) + struct.pack(">H", 0x0100)
        p += b"\x00" * 10 + _MATRIX + b"\x00" * 24 + struct.pack(">I", next_id)
        return _fbox(b"mvhd", 0, 0, p)

    def tkhd(tid, w, h, vol=0):
        p = struct.pack(">IIIII", 0, 0, tid, 0, 2000) + b"\x00" * 8
        p += struct.pack(">HHHH", 0, 0, vol, 0) + _MATRIX
        p += struct.pack(">II", w << 16, h << 16)
        return _fbox(b"tkhd", 0, 7, p)

    def mdhd():
        return _fbox(b"mdhd", 0, 0,
                     struct.pack(">IIIIHH", 0, 0, 1000, 2000, 0x55C4, 0))

    def hdlr(handler, name):
        return _fbox(b"hdlr", 0, 0,
                     struct.pack(">I", 0) + handler + b"\x00" * 12 +
                     name + b"\x00")

    def dref():
        return _fbox(b"dref", 0, 0,
                     struct.pack(">I", 1) + _fbox(b"url ", 0, 1, b""))

    def avc1():
        p = b"\x00" * 6 + struct.pack(">H", 1) + b"\x00" * 16
        p += struct.pack(">HHIII", 320, 240, 0x480000, 0x480000, 0)
        p += struct.pack(">H", 1) + b"\x00" * 32 + struct.pack(">HH", 0x18, 0xFFFF)
        avcc = (b"\x01\x42\xc0\x1e\xff\xe1\x00\x09\x67\x42\xc0\x1e\xd9\x00"
                b"\xf0\x11\x7e\x01\x00\x04\x68\xce\x3c\x80")
        return _box(b"avc1", p + _box(b"avcC", avcc))

    def mp4a():
        p = b"\x00" * 6 + struct.pack(">H", 1) + struct.pack(">II", 0, 0)
        p += struct.pack(">HHHH", 2, 16, 0, 0) + struct.pack(">I", 44100 << 16)
        dsi = b"\x12\x10"
        ds = b"\x05" + bytes([len(dsi)]) + dsi
        dc = b"\x04" + bytes([13 + len(ds)]) + b"\x40\x15" + b"\x00" * 11 + ds
        sl = b"\x06\x01\x02"
        es = b"\x03" + bytes([3 + len(dc) + len(sl)]) + b"\x00\x00\x00" + dc + sl
        return _box(b"mp4a", p + _fbox(b"esds", 0, 0, es))

    def stbl(entry, sizes, off, sync=False):
        s = _fbox(b"stsd", 0, 0, struct.pack(">I", 1) + entry)
        s += _fbox(b"stts", 0, 0, struct.pack(">III", 1, len(sizes), 1000))
        s += _fbox(b"stsc", 0, 0, struct.pack(">IIII", 1, 1, len(sizes), 1))
        s += _fbox(b"stsz", 0, 0,
                   struct.pack(">II", 0, len(sizes)) +
                   b"".join(struct.pack(">I", x) for x in sizes))
        s += _fbox(b"stco", 0, 0, struct.pack(">II", 1, off))
        if sync:
            s += _fbox(b"stss", 0, 0, struct.pack(">II", 1, 1))
            s += _fbox(b"ctts", 0, 0, struct.pack(">III", 1, len(sizes), 0))
        return _box(b"stbl", s)

    def trak(tid, w, h, handler, name, mhd, entry, sizes, off, vol=0,
             sync=False, edts=False):
        minf = _box(b"minf", mhd + _box(b"dinf", dref()) +
                    stbl(entry, sizes, off, sync))
        mdia = _box(b"mdia", mdhd() + hdlr(handler, name) + minf)
        body = tkhd(tid, w, h, vol)
        if edts:
            body += _box(b"edts", _fbox(b"elst", 0, 0,
                         struct.pack(">IIiHH", 1, 2000, 0, 1, 0)))
        return _box(b"trak", body + mdia)

    vmhd = _fbox(b"vmhd", 0, 1, b"\x00" * 8)
    smhd = _fbox(b"smhd", 0, 0, b"\x00" * 4)

    if not fragmented:
        moov = _box(b"moov", mvhd(4) +
                    trak(1, 320, 240, b"vide", b"VideoHandler", vmhd, avc1(),
                         [40, 30], 9999, sync=True, edts=True) +
                    trak(2, 0, 0, b"soun", b"SoundHandler", smhd, mp4a(),
                         [20, 20], 9999, vol=0x0100))
        off = len(ftyp) + len(moov) + 8
        moov = _box(b"moov", mvhd(4) +
                    trak(1, 320, 240, b"vide", b"VideoHandler", vmhd, avc1(),
                         [40, 30], off, sync=True, edts=True) +
                    trak(2, 0, 0, b"soun", b"SoundHandler", smhd, mp4a(),
                         [20, 20], off + 70, vol=0x0100))
        return ftyp + moov + _box(b"mdat", b"\x00" * 120)

    # fragmented
    def empty_trak():
        s = _fbox(b"stsd", 0, 0, struct.pack(">I", 1) + avc1())
        for t in (b"stts", b"stsc", b"stco"):
            s += _fbox(t, 0, 0, struct.pack(">I", 0))
        s += _fbox(b"stsz", 0, 0, struct.pack(">II", 0, 0))
        minf = _box(b"minf", vmhd + _box(b"dinf", dref()) + _box(b"stbl", s))
        mdia = _box(b"mdia", mdhd() + hdlr(b"vide", b"VideoHandler") + minf)
        return _box(b"trak", tkhd(1, 320, 240) + mdia)

    mvex = _box(b"mvex",
                _fbox(b"mehd", 0, 0, struct.pack(">I", 4000)) +
                _fbox(b"trex", 0, 0,
                      struct.pack(">IIIII", 1, 1, 40, 0, 0x02000000)))
    moov = _box(b"moov", mvhd(2) + empty_trak() + mvex)
    trun = _fbox(b"trun", 0, 0x000301,
                 struct.pack(">Ii", 3, 0) +
                 b"".join(struct.pack(">II", 1000, 50) for _ in range(3)))
    traf = _box(b"traf",
                _fbox(b"mfhd", 0, 0, struct.pack(">I", 1)) +
                _fbox(b"tfhd", 0, 0x020008, struct.pack(">II", 1, 40)) +
                _fbox(b"tfdt", 0, 0, struct.pack(">I", 0)) + trun)
    moof = _box(b"moof", traf)
    return ftyp + moov + moof + _box(b"mdat", b"\x00" * 150)


def synthetic():
    """Return {harness: {filename: bytes}} of synthesised seeds."""
    pa = {}

    # RIFF family
    pa["gen.wav"] = _riff(b"WAVE", [
        _chunk(b"fmt ", struct.pack("<HHIIHH", 1, 2, 44100, 176400, 4, 16)),
        _chunk(b"data", b"\x01\x02" * 256)])
    pa["gen_f32.wav"] = _riff(b"WAVE", [
        _chunk(b"fmt ", struct.pack("<HHIIHH", 3, 1, 48000, 192000, 4, 32)),
        _chunk(b"data", b"\x00" * 512)])
    pa["gen.qcp"] = _riff(b"QLCM", [
        _chunk(b"fmt ", struct.pack("<H", 1) + b"\x00" * 148),
        _chunk(b"data", b"\x00" * 64)])
    avih = struct.pack("<16I", 33333, 1000000, 0, 0x10, 30, 0, 1, 0,
                       320, 240, 0, 0, 0, 0, 0, 0)
    strh = struct.pack("<4s4sIHHIIIIIIIIHHHH", b"vids", b"MJPG", 0, 0, 0, 0,
                       1, 30, 0, 30, 0, 0, 0, 0, 0, 320, 240)
    strf = struct.pack("<IiiHHIIiiII", 40, 320, 240, 1, 24, 0, 0, 0, 0, 0, 0)
    hdrl = _chunk(b"LIST", b"hdrl" + _chunk(b"avih", avih) +
                  _chunk(b"LIST", b"strl" + _chunk(b"strh", strh) +
                         _chunk(b"strf", strf)))
    movi = _chunk(b"LIST", b"movi" +
                  _chunk(b"00dc", b"\xff\xd8\xff\xe0" + b"\x00" * 32))
    pa["gen.avi"] = _riff(b"AVI ", [hdrl, movi])

    # AIFF
    body = b"AIFF"
    comm = b"COMM" + struct.pack(">I", 18) + struct.pack(">hIh", 2, 256, 16)
    comm += b"\x40\x0e\xac\x44\x00\x00\x00\x00\x00\x00"
    ssnd = b"SSND" + struct.pack(">I", 136) + b"\x00" * 136
    pa["gen.aif"] = b"FORM" + struct.pack(">I", len(body + comm + ssnd)) + \
        body + comm + ssnd

    # OGG vorbis + opus
    vid = b"\x01vorbis" + struct.pack("<IBIiiiB", 0, 2, 44100, 0, 128000, 0,
                                      (6 << 4) | 4) + b"\x01"
    vcm = b"\x03vorbis" + struct.pack("<I", 4) + b"GPAC" + \
        struct.pack("<I", 0) + b"\x01"
    pa["gen.ogg"] = (_ogg_page(1, 0, 0, [vid], 2) +
                     _ogg_page(1, 1, 0, [vcm, b"\x05vorbis" + b"\x00" * 32]) +
                     _ogg_page(1, 2, 1024, [b"\x00" * 48], 4))
    oh = b"OpusHead" + struct.pack("<BBHIhB", 1, 2, 312, 48000, 0, 0)
    ot = b"OpusTags" + struct.pack("<I", 4) + b"GPAC" + struct.pack("<I", 0)
    pa["gen_opus.ogg"] = (_ogg_page(7, 0, 0, [oh], 2) +
                          _ogg_page(7, 1, 0, [ot]) +
                          _ogg_page(7, 2, 960, [b"\xfc\xff\xfe"], 4))

    # FLV
    flv = b"FLV" + bytes([1, 5]) + struct.pack(">II", 9, 0)
    meta = b"\x02" + struct.pack(">H", 10) + b"onMetaData"
    meta += b"\x08" + struct.pack(">I", 1)
    meta += struct.pack(">H", 8) + b"duration" + b"\x00" + struct.pack(">d", 1.0)
    meta += b"\x00\x00\x09"
    flv += bytes([18]) + struct.pack(">I", len(meta))[1:] + b"\x00" * 5 + meta
    flv += struct.pack(">I", len(meta) + 11)
    aud = bytes([0x2F]) + b"\x00" * 16
    flv += bytes([8]) + struct.pack(">I", len(aud))[1:] + b"\x00" * 5 + aud
    flv += struct.pack(">I", len(aud) + 11)
    vid2 = bytes([0x17, 0x00]) + b"\x00" * 20
    flv += bytes([9]) + struct.pack(">I", len(vid2))[1:] + b"\x00" * 5 + vid2
    flv += struct.pack(">I", len(vid2) + 11)
    pa["gen.flv"] = flv

    # GIF / BMP
    pa["gen.gif"] = (b"GIF89a" + struct.pack("<HH", 4, 4) + bytes([0xF0, 0, 0]) +
                     b"\x00\x00\x00\xff\xff\xff" +
                     b"\x21\xf9\x04\x00\x00\x00\x00\x00" +
                     b"\x2c" + struct.pack("<HHHH", 0, 0, 4, 4) + bytes([0]) +
                     bytes([2]) + b"\x02\x4c\x01\x00" + bytes([0]) + b"\x3b")
    px = b"\xff\x00\x00\x00" * 16
    dib = struct.pack("<IiiHHIIiiII", 40, 4, 4, 1, 32, 0, len(px),
                      2835, 2835, 0, 0)
    pa["gen.bmp"] = b"BM" + struct.pack("<IHHI", 14 + len(dib) + len(px),
                                        0, 0, 14 + len(dib)) + dib + px

    # AMR / FLAC / AC-3 / DTS
    pa["gen.amr"] = b"#!AMR\n" + (b"\x3c" + b"\x00" * 12) * 2
    pa["gen_wb.amr"] = b"#!AMR-WB\n" + b"\x04" + b"\x00" * 17
    si = struct.pack(">HHII", 4096, 4096, 0, 0)
    si += struct.pack(">Q", (44100 << 44) | (1 << 41) | (15 << 36))
    si += b"\x00" * 16
    pa["gen.flac"] = (b"fLaC" + bytes([0x80]) + struct.pack(">I", len(si))[1:] +
                      si + b"\xff\xf8\x69\x08" + b"\x00" * 16)
    pa["gen.ac3"] = (b"\x0b\x77" + b"\x00" * 126) * 2
    pa["gen.dts"] = (b"\x7f\xfe\x80\x01" + b"\x00" * 92) * 2

    # MPEG program stream
    ps = b"\x00\x00\x01\xba" + b"\x44\x00\x04\x00\x04\x01\x01\x89\xc3\xf8"
    ps += b"\x00\x00\x01\xbb" + struct.pack(">H", 12) + b"\x80\x14\xe0" + \
        b"\x00" * 9
    pes = b"\x00\x00\x00\x01\x09\x10" + b"\x00" * 32
    ps += b"\x00\x00\x01\xe0" + struct.pack(">H", len(pes) + 3) + \
        b"\x80\x00\x00" + pes + b"\x00\x00\x01\xb9"
    pa["gen.mpg"] = ps

    # MPEG-TS / M2TS
    pat = bytes([0x00, 0xB0, 0x0D, 0x00, 0x01, 0xC1, 0x00, 0x00])
    pat += struct.pack(">HH", 0x0001, 0xE100) + b"\x00\x00\x00\x00"
    pat = _ts_packet(0x0000, pat)
    pmt = bytes([0x02, 0xB0, 0x17, 0x00, 0x01, 0xC1, 0x00, 0x00])
    pmt += struct.pack(">HH", 0xE101, 0xF000)
    pmt += bytes([0x1B]) + struct.pack(">HH", 0xE101, 0xF000) + b"\x00\x00\x00\x00"
    pmt = _ts_packet(0x0100, pmt)
    pesb = b"\x00\x00\x01\xe0\x00\x00\x80\x80\x05\x21\x00\x01\x00\x01"
    pesb += b"\x00\x00\x00\x01\x67\x42\x00\x1e" + b"\x00" * 20
    pesb += b"\x00\x00\x00\x01\x65" + b"\x00" * 60
    es = _ts_packet(0x0101, pesb)
    ts = (pat + pmt + es) * 4
    pa["gen.ts"] = ts
    m2ts = b"".join(struct.pack(">I", i) +
                    (pat if i == 0 else pmt if i == 1 else es)
                    for i in range(8))
    pa["gen.m2ts"] = m2ts

    # Matroska / WebM
    info = _el(0x1549A966, _el_u(0x2AD7B1, 1000000) + _el_f(0x4489, 1000.0) +
               _el_s(0x4D80, "GPAC") + _el_s(0x5741, "GPAC"))
    tv = _el(0xAE, _el_u(0xD7, 1) + _el_u(0x73C5, 1) + _el_u(0x83, 1) +
             _el_s(0x86, "V_MPEG4/ISO/AVC") +
             _el(0xE0, _el_u(0xB0, 320) + _el_u(0xBA, 240)))
    ta = _el(0xAE, _el_u(0xD7, 2) + _el_u(0x73C5, 2) + _el_u(0x83, 2) +
             _el_s(0x86, "A_AAC") +
             _el(0xE1, _el_f(0xB5, 44100.0) + _el_u(0x9F, 2)))
    cluster = _el(0x1F43B675, _el_u(0xE7, 0) +
                  _el(0xA3, b"\x81\x00\x00\x80" + b"\x00" * 32))

    def ebml_hdr(doctype, ver):
        return _el(0x1A45DFA3,
                   _el_u(0x4286, 1) + _el_u(0x42F7, 1) + _el_u(0x42F2, 4) +
                   _el_u(0x42F3, 8) + _el_s(0x4282, doctype) +
                   _el_u(0x4287, ver) + _el_u(0x4285, 2))

    pa["gen.mkv"] = ebml_hdr("matroska", 4) + _el(
        0x18538067, info + _el(0x1654AE6B, tv + ta) + cluster)
    tvp = _el(0xAE, _el_u(0xD7, 1) + _el_u(0x73C5, 1) + _el_u(0x83, 1) +
              _el_s(0x86, "V_VP9") +
              _el(0xE0, _el_u(0xB0, 320) + _el_u(0xBA, 240)))
    pa["gen.webm"] = ebml_hdr("webm", 2) + _el(
        0x18538067, info + _el(0x1654AE6B, tvp) + cluster)

    # NHML
    pa["gen.nhml"] = (b'<?xml version="1.0"?>\n<NHNTStream version="1.0" '
                      b'streamType="4" objectTypeIndication="33" '
                      b'timeScale="1000" width="320" height="240">\n'
                      b'<NHNTSample DTS="0" dataLength="4" isRAP="yes"/>\n'
                      b'</NHNTStream>\n')

    # raw elementary streams
    pa["gen.264"] = (b"\x00\x00\x00\x01\x67\x42\xc0\x1e\xd9\x00\xf0\x11\x7e"
                     b"\xf0\x11\x00\x00\x00\x01\x68\xce\x3c\x80"
                     b"\x00\x00\x00\x01\x65\x88\x84\x00" + b"\x00" * 32)
    pa["gen.hvc"] = (b"\x00\x00\x00\x01\x40\x01\x0c\x01\xff\xff" + b"\x00" * 12 +
                     b"\x00\x00\x00\x01\x42\x01\x01" + b"\x00" * 16 +
                     b"\x00\x00\x00\x01\x44\x01" + b"\x00" * 8 +
                     b"\x00\x00\x00\x01\x26\x01" + b"\x00" * 40)
    id3 = b"ID3\x03\x00\x00\x00\x00\x00\x20"
    id3 += b"TIT2" + struct.pack(">I", 5) + b"\x00\x00\x00GPAC"
    id3 += b"\x00" * (0x20 - 11)
    pa["gen_id3.mp3"] = id3 + (b"\xff\xfb\x90\x00" + b"\x00" * 100) * 4
    pa["gen.aac"] = b"".join(_adts(48) for _ in range(6))
    pa["gen.m4v"] = (b"\x00\x00\x01\xb0\x01" +
                     b"\x00\x00\x01\xb5\x09\x00\x00\x00" +
                     b"\x00\x00\x01\x00" + b"\x00" * 12 +
                     b"\x00\x00\x01\x20\x08" + b"\x00" * 12 +
                     b"\x00\x00\x01\xb6" + b"\x00" * 40)
    pa["gen.m1v"] = (b"\x00\x00\x01\xb3\x14\x00\xf0\xc4\x02\x0a\x00\x00" +
                     b"\x00\x00\x01\xb8\x00\x00\x00\x00" +
                     b"\x00\x00\x01\x00\x00\x00\x00\x00" +
                     b"\x00\x00\x01\x01" + b"\x00" * 40)

    # subtitles / text
    pa["gen.srt"] = (b"1\n00:00:00,000 --> 00:00:02,000\nHello <b>GPAC</b>\n\n"
                     b"2\n00:00:02,000 --> 00:00:04,000\nSecond line\n\n")
    pa["gen.vtt"] = (b"WEBVTT\n\n00:00:00.000 --> 00:00:02.000\nHello\n\n"
                     b"00:00:02.000 --> 00:00:04.000 position:50%\nWorld\n")
    pa["gen.ttml"] = (b'<?xml version="1.0"?><tt '
                      b'xmlns="http://www.w3.org/ns/ttml"><body><div>'
                      b'<p begin="0s" end="2s">Hello</p></div></body></tt>')
    pa["gen.sub"] = b"{1}{50}First subtitle\n{51}{100}Second subtitle\n"
    pa["gen.ttxt"] = (b'<?xml version="1.0"?><TextStream version="1.1">'
                      b'<TextStreamHeader><TextSampleDescription/>'
                      b'</TextStreamHeader><TextSample '
                      b'sampleTime="00:00:00.000">Hi</TextSample></TextStream>')

    # DASH / HLS manifests (segments resolve locally and are absent -> no I/O)
    pa["gen.mpd"] = (b'<?xml version="1.0"?>\n<MPD '
                     b'xmlns="urn:mpeg:dash:schema:mpd:2011" type="static" '
                     b'mediaPresentationDuration="PT10S" '
                     b'profiles="urn:mpeg:dash:profile:isoff-on-demand:2011">\n'
                     b'<Period><AdaptationSet mimeType="video/mp4">'
                     b'<Representation id="1" bandwidth="100000" '
                     b'codecs="avc1.42c01e"><BaseURL>v.mp4</BaseURL>'
                     b'<SegmentBase indexRange="0-100"/></Representation>'
                     b'</AdaptationSet></Period></MPD>\n')
    pa["gen.m3u8"] = (b"#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:10\n"
                      b"#EXT-X-MEDIA-SEQUENCE:0\n#EXTINF:9.0,\nseg0.ts\n"
                      b"#EXTINF:9.0,\nseg1.ts\n#EXT-X-ENDLIST\n")
    pa["gen_master.m3u8"] = (b"#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=100000,"
                             b"RESOLUTION=320x240\nlow.m3u8\n")

    # scene formats
    pa["gen.svg"] = (b'<?xml version="1.0"?><svg '
                     b'xmlns="http://www.w3.org/2000/svg" width="100" '
                     b'height="100"><rect x="10" y="10" width="80" '
                     b'height="80" fill="red"/><circle cx="50" cy="50" '
                     b'r="20" fill="blue"/></svg>')
    pa["gen.xmt"] = (b'<?xml version="1.0"?>'
                     b'<XMT-A xmlns="urn:mpeg:mpeg4:xmta:schema:2002">'
                     b'<Header/><Body><Replace><Scene><Group/></Scene>'
                     b'</Replace></Body></XMT-A>')
    pa["gen.bt"] = (b"InitialObjectDescriptor { objectDescriptorID 1 }\n"
                    b"OrderedGroup { children [ Shape {\n"
                    b" appearance Appearance { material Material2D "
                    b"{ emissiveColor 1 0 0 } }\n"
                    b" geometry Rectangle { size 100 100 } } ] }\n")

    # ISOBMFF
    pa["gen_regular.mp4"] = _mp4(fragmented=False)
    pa["gen_frag.mp4"] = _mp4(fragmented=True)

    parse = {"gen_regular.mp4": pa["gen_regular.mp4"],
             "gen_frag.mp4": pa["gen_frag.mp4"]}
    m2ts = {"gen.ts": pa["gen.ts"], "gen.m2ts": pa["gen.m2ts"]}
    return {"fuzz_probe_analyze": pa, "fuzz_parse": parse,
            "fuzz_m2ts_probe": m2ts}


# --------------------------------------------------------------------------
# real samples already present in the gpac testsuite checkout
# --------------------------------------------------------------------------
def _collect(root, patterns, limit):
    found = []
    for dirpath, _, files in os.walk(root):
        for name in sorted(files):
            if any(name.lower().endswith(s) for s in patterns):
                found.append(os.path.join(dirpath, name))
            if len(found) >= limit:
                return found
    return found


def testsuite_samples(testsuite_dir):
    """Return {harness: {filename: bytes}} sourced from the testsuite."""
    pa, parse, m2ts = {}, {}, {}
    media = os.path.join(testsuite_dir, "media")
    aux = os.path.join(media, "auxiliary_files")

    def add(dst, path, prefix=""):
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            return
        if not data:
            return
        dst[prefix + os.path.basename(path)] = data

    # real elementary streams / images / subtitles
    if os.path.isdir(aux):
        for name in sorted(os.listdir(aux)):
            add(pa, os.path.join(aux, name))

    # scene/text samples — broad coverage of BIFS/X3D/SVG node types
    for ext, limit, pref in ((".bt", 130, "bt_"), (".svg", 45, "svg_"),
                             (".vtt", 15, "vtt_"), (".ttml", 12, "ttml_"),
                             (".x3dv", 22, "x3d_"), (".x3d", 8, "x3da_"),
                             (".xmt", 12, "xmt_"), (".wrl", 8, "wrl_"),
                             (".xmta", 4, "xmta_")):
        for i, path in enumerate(_collect(media, (ext,), limit)):
            add(pa, path, prefix=f"{pref}{i}_")

    # existing fuzz_parse corpus (ISOBMFF)
    pc = os.path.join(testsuite_dir, "oss-fuzzers", "fuzz_parse_corpus")
    if os.path.isdir(pc):
        for name in sorted(os.listdir(pc)):
            add(parse, os.path.join(pc, name))
            add(pa, os.path.join(pc, name))

    # ISOBMFF-flavoured samples for fuzz_parse (<= 64 KiB harness cap)
    for path in _collect(media, (".mp4", ".ismv", ".ismt", ".iamf"), 40):
        if os.path.getsize(path) <= 65536:
            add(parse, path)

    return {"fuzz_probe_analyze": pa, "fuzz_parse": parse,
            "fuzz_m2ts_probe": m2ts}


# Extension table — MUST stay in sync with exts[] in fuzz_demux.c /
# fuzz_render.c. The first byte of each input selects an extension here, so
# the extension-driven text/scene source filters become reachable.
EXTS = ["mp4", "mov", "m4a", "3gp", "heif", "avif", "mj2", "ismv", "ismt",
        "iamf", "ts", "m2ts", "mkv", "webm", "avi", "flv", "ogg", "mpg",
        "vob", "mp3", "aac", "ac3", "amr", "flac", "wav", "qcp", "aif",
        "dts", "au", "h264", "h265", "av1", "obu", "ivf", "cmp", "m4v",
        "m1v", "vvc", "jpg", "png", "bmp", "gif", "jp2", "bt", "xmt",
        "wrl", "x3d", "x3dv", "svg", "swf", "saf", "mpd", "m3u8", "srt",
        "vtt", "ttml", "sub", "ttxt", "ssa", "nhml", "nhnt", "gsf", "sdp"]
_EXT_IDX = {e: i for i, e in enumerate(EXTS)}
_EXT_ALIAS = {"264": "h264", "hvc": "h265", "hevc": "h265", "jpeg": "jpg",
              "h265": "h265", "qt": "mov"}


def _selector(name):
    """First-byte selector that maps a seed file to its real extension."""
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    ext = _EXT_ALIAS.get(ext, ext)
    return _EXT_IDX.get(ext, 0)


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: gen_fuzz_seeds.py <testsuite_dir> <out_dir>")
    testsuite_dir, out_dir = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)

    corpora = {}
    for src in (synthetic(), testsuite_samples(testsuite_dir)):
        for harness, files in src.items():
            corpora.setdefault(harness, {}).update(files)

    # fuzz_demux / fuzz_render consume an extension-selector byte followed by
    # the file body: reuse every probe_analyze seed with the right prefix.
    base = corpora.get("fuzz_probe_analyze", {})
    for harness in ("fuzz_demux", "fuzz_render"):
        corpora[harness] = {
            name: bytes([_selector(name)]) + data
            for name, data in base.items()
        }

    for harness, files in corpora.items():
        if not files:
            continue
        zip_path = os.path.join(out_dir, f"{harness}_seed_corpus.zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
            for name, data in sorted(files.items()):
                z.writestr(name, data)
        print(f"{harness}: {len(files)} seeds -> {zip_path}")


if __name__ == "__main__":
    main()
