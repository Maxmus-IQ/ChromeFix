#!/usr/bin/env python3
"""
fix_appzygote.py -- Fix the Chromium / app-zygote NPE in an Android services.jar.

Symptom it fixes:
    java.lang.NullPointerException: Attempt to read from field
    'int com.android.server.am.ProcessList$IsolatedUidRange.mFirstUid'
    on a null object reference
    at com.android.server.am.ProcessList.createAppZygoteForProcessIfNeeded(ProcessList.java)
    -> every Chromium browser shows blank pages (even chrome://flags)
    -> no app zygote is ever created

Cause:
    OEM builds (Xiaomi/HyperOS, ColorOS, ...) carry a modified ProcessList where
    createAppZygoteForProcessIfNeeded() has two branches:

        if (Flags.useSafesetidUidPolicy2() && UidTransitionPolicy.isEnabled()
                && getUidTransitionPolicy() != null) {
            ... uses mGlobalAppIsolatedUids ...
        } else {
            IsolatedUidRange r = mAppIsolatedUidRangeAllocator
                    .getIsolatedUidRangeLocked(processName, uid);   // <-- can return null
            ... r.mFirstUid ...                                    // <-- NPE
        }

    On many ported ROMs the safesetid policy file is unwritable, so the first
    branch is never taken and the allocator has never populated a per-app range,
    so getIsolatedUidRangeLocked() returns null and the framework crashes.

Fix (identical to upstream AOSP / LineageOS change I093c5ef5aef):
    call getOrCreateIsolatedUidRangeLocked() instead, which creates the range
    when missing. Same class, same prototype -> a one-byte method-index change.

Usage:
    python3 fix_appzygote.py services.jar
    python3 fix_appzygote.py services.jar -o services.patched.jar
    python3 fix_appzygote.py services.jar --module chromefix-module.zip

Author: written for ROM porters. No dependencies beyond Python 3.
"""

import argparse
import hashlib
import os
import shutil
import struct
import sys
import zipfile
import zlib

PROCESSLIST = "Lcom/android/server/am/ProcessList;"
ALLOCATOR = "Lcom/android/server/am/ProcessList$IsolatedUidRangeAllocator;"
TARGET_METHOD = "createAppZygoteForProcessIfNeeded"
BUGGY_CALL = "getIsolatedUidRangeLocked"
SAFE_CALL = "getOrCreateIsolatedUidRangeLocked"

# ----------------------------------------------------------------------------
# DEX parsing
# ----------------------------------------------------------------------------

# instruction widths in 16-bit code units; 0 means "unused/unknown"
WIDTH = [1] * 256
for _o, _w in {
    0x00: 1, 0x01: 1, 0x02: 2, 0x03: 3, 0x04: 1, 0x05: 2, 0x06: 3,
    0x07: 1, 0x08: 2, 0x09: 3, 0x0a: 1, 0x0b: 1, 0x0c: 1, 0x0d: 1,
    0x0e: 1, 0x0f: 1, 0x10: 1, 0x11: 1, 0x12: 1, 0x13: 2, 0x14: 3,
    0x15: 2, 0x16: 2, 0x17: 3, 0x18: 5, 0x19: 2, 0x1a: 2, 0x1b: 3,
    0x1c: 2, 0x1d: 1, 0x1e: 1, 0x1f: 2, 0x20: 2, 0x21: 1, 0x22: 2,
    0x23: 2, 0x24: 3, 0x25: 3, 0x26: 3, 0x27: 1, 0x28: 1, 0x29: 2,
    0x2a: 3, 0x2b: 3, 0x2c: 3,
    0x2d: 2, 0x2e: 2, 0x2f: 2, 0x30: 2, 0x31: 2,
    0x32: 2, 0x33: 2, 0x34: 2, 0x35: 2, 0x36: 2, 0x37: 2,
    0x38: 2, 0x39: 2, 0x3a: 2, 0x3b: 2, 0x3c: 2, 0x3d: 2,
    0x3e: 0, 0x3f: 0, 0x40: 0, 0x41: 0, 0x42: 0, 0x43: 0,
    0x44: 2, 0x45: 2, 0x46: 2, 0x47: 2, 0x48: 2, 0x49: 2, 0x4a: 2, 0x4b: 2,
    0x4c: 2, 0x4d: 2, 0x4e: 2, 0x4f: 2, 0x50: 2, 0x51: 2,
    0x52: 2, 0x53: 2, 0x54: 2, 0x55: 2, 0x56: 2, 0x57: 2, 0x58: 2, 0x59: 2,
    0x5a: 2, 0x5b: 2, 0x5c: 2, 0x5d: 2, 0x5e: 2, 0x5f: 2,
    0x60: 2, 0x61: 2, 0x62: 2, 0x63: 2, 0x64: 2, 0x65: 2, 0x66: 2, 0x67: 2,
    0x68: 2, 0x69: 2, 0x6a: 2, 0x6b: 2, 0x6c: 2, 0x6d: 2,
    0x6e: 3, 0x6f: 3, 0x70: 3, 0x71: 3, 0x72: 3, 0x73: 0,
    0x74: 3, 0x75: 3, 0x76: 3, 0x77: 3, 0x78: 3, 0x79: 0, 0x7a: 0,
}.items():
    WIDTH[_o] = _w
for _o in range(0x7b, 0x90):
    WIDTH[_o] = 1
for _o in range(0x90, 0xe3):
    WIDTH[_o] = 2

INVOKE_VIRTUAL = {0x6e: "invoke-virtual", 0x74: "invoke-virtual/range"}


def _uleb(d, p):
    r = 0
    s = 0
    while True:
        b = d[p]
        p += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80):
            break
        s += 7
    return r, p


class Dex:
    def __init__(self, data, name="classes.dex"):
        self.d = data
        self.name = name
        d = data
        if d[:4] != b"dex\n":
            raise ValueError(f"{name}: not a dex file")
        # NOTE: endian_tag lives at 0x28 -- forgetting it shifts every offset by 4
        self.n_str = int.from_bytes(d[0x38:0x3C], "little")
        self.o_str = int.from_bytes(d[0x3C:0x40], "little")
        self.n_type = int.from_bytes(d[0x40:0x44], "little")
        self.o_type = int.from_bytes(d[0x44:0x48], "little")
        self.o_proto = int.from_bytes(d[0x4C:0x50], "little")
        self.n_method = int.from_bytes(d[0x58:0x5C], "little")
        self.o_method = int.from_bytes(d[0x5C:0x60], "little")
        self.n_class = int.from_bytes(d[0x60:0x64], "little")
        self.o_class = int.from_bytes(d[0x64:0x68], "little")
        self._str = {}

    def string(self, i):
        if i in self._str:
            return self._str[i]
        d = self.d
        if i >= self.n_str:
            self._str[i] = f"<bad_string_idx:{i}>"
            return self._str[i]
        off = int.from_bytes(d[self.o_str + 4 * i:self.o_str + 4 * i + 4], "little")
        p = off
        _, p = _uleb(d, p)
        start = p
        while p < len(d) and d[p] != 0:
            p += 1
        self._str[i] = d[start:p].decode("utf-8", "replace")
        return self._str[i]

    def type(self, i):
        d = self.d
        if i >= self.n_type:
            return f"<bad_type:{i}>"
        idx = int.from_bytes(d[self.o_type + 4 * i:self.o_type + 4 * i + 4], "little")
        return self.string(idx)

    def proto(self, i):
        d = self.d
        base = self.o_proto + 12 * i
        ret = int.from_bytes(d[base + 4:base + 8], "little")
        poff = int.from_bytes(d[base + 8:base + 12], "little")
        out = [self.type(ret)]
        if poff:
            n = int.from_bytes(d[poff:poff + 4], "little")
            for k in range(n):  # type_list entries are USHORT, not uint
                t = int.from_bytes(d[poff + 4 + 2 * k:poff + 6 + 2 * k], "little")
                out.append(self.type(t))
        return tuple(out)

    def method(self, i):
        d = self.d
        base = self.o_method + 8 * i
        cls = int.from_bytes(d[base:base + 2], "little")
        proto = int.from_bytes(d[base + 2:base + 4], "little")
        name = int.from_bytes(d[base + 4:base + 8], "little")
        return self.type(cls), self.string(name), proto

    def find_class(self, desc):
        d = self.d
        for i in range(self.n_class):
            base = self.o_class + 32 * i
            if self.type(int.from_bytes(d[base:base + 4], "little")) == desc:
                return i
        return None

    def class_methods(self, ci):
        d = self.d
        base = self.o_class + 32 * ci
        cdo = int.from_bytes(d[base + 24:base + 28], "little")
        if not cdo:
            return []
        p = cdo
        sf, p = _uleb(d, p)
        inf, p = _uleb(d, p)
        dm, p = _uleb(d, p)
        vm, p = _uleb(d, p)
        for _ in range(sf + inf):
            _, p = _uleb(d, p)
            _, p = _uleb(d, p)
        res = []
        for kind, cnt in (("direct", dm), ("virtual", vm)):
            mi = 0
            for _ in range(cnt):
                diff, p = _uleb(d, p)
                _, p = _uleb(d, p)
                code, p = _uleb(d, p)
                mi += diff
                res.append((mi, kind, code))
        return res

    def invokes(self, code_off):
        """Yield (insn_offset_in_file, opcode, method_idx) for invoke-virtual insns."""
        d = self.d
        insns_off = code_off + 16
        n = int.from_bytes(d[code_off + 12:code_off + 16], "little")
        k = 0
        while k < n:
            off = insns_off + 2 * k
            op = d[off] & 0xFF
            if op in INVOKE_VIRTUAL:
                m = int.from_bytes(d[off + 2:off + 4], "little")
                yield off, op, m
            k += WIDTH[op] or 1


# ----------------------------------------------------------------------------
# Patch logic
# ----------------------------------------------------------------------------

def find_patch(dex):
    """Return (call_file_off, old_idx, new_idx) or raise with a reason."""
    ci = dex.find_class(PROCESSLIST)
    if ci is None:
        raise LookupError(f"ProcessList not found in {dex.name}")

    methods = dex.class_methods(ci)
    target_code = None
    for mi, kind, code in methods:
        _, name, _ = dex.method(mi)
        if name == TARGET_METHOD:
            target_code = code
            break
    if target_code is None:
        raise LookupError(f"{TARGET_METHOD} not found in {dex.name}")

    buggy = None
    for off, op, midx in dex.invokes(target_code):
        cls, name, proto = dex.method(midx)
        if cls == ALLOCATOR and name == BUGGY_CALL:
            buggy = (off, midx, proto)
            break
    if buggy is None:
        raise LookupError(
            f"no {BUGGY_CALL}() call inside {TARGET_METHOD} in {dex.name} "
            f"(already fixed, or not an affected OEM build)"
        )

    off, old_idx, proto = buggy
    # find a method with the same class + prototype called getOrCreate...
    new_idx = None
    for mi, kind, code in methods:
        cls, name, p = dex.method(mi)
        if cls == ALLOCATOR and name == SAFE_CALL and p == proto:
            new_idx = mi
            break
    if new_idx is None:
        for i in range(dex.n_method):
            cls, name, p = dex.method(i)
            if cls == ALLOCATOR and name == SAFE_CALL and p == proto:
                new_idx = i
                break
    if new_idx is None:
        raise LookupError(
            f"{SAFE_CALL}() with matching prototype not found in {dex.name}"
        )
    return off, old_idx, new_idx


def patch_dex(data, off, old_idx, new_idx):
    d = bytearray(data)
    cur = int.from_bytes(d[off + 2:off + 4], "little")
    if cur != old_idx:
        raise ValueError(f"sanity: method_idx at {off:#x} is {cur}, expected {old_idx}")
    d[off + 2] = new_idx & 0xFF
    d[off + 3] = (new_idx >> 8) & 0xFF
    d[0x0C:0x20] = hashlib.sha1(bytes(d[0x20:])).digest()
    d[0x08:0x0C] = (zlib.adler32(bytes(d[0x0C:])) & 0xFFFFFFFF).to_bytes(4, "little")
    return bytes(d), d


def repack(src, dst, replacement):
    """Copy every entry of src into dst, substituting `replacement[filename]`."""
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w") as zout:
        for info in zin.infolist():
            data = replacement.get(info.filename, zin.read(info.filename))
            ni = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            ni.create_system = info.create_system
            ni.external_attr = info.external_attr
            ni.compress_type = info.compress_type
            zout.writestr(ni, data)


MODULE_PROP = """id=chromefix
name=Chromium app-zygote NPE fix
version=v2
versionCode=2
author=local
description=Fixes blank pages in all Chromium browsers by patching ProcessList.createAppZygoteForProcessIfNeeded to call getOrCreateIsolatedUidRangeLocked (upstream AOSP I093c5ef5aef). Works on Magisk magic mount, KernelSU, and KernelSU metamodules (metamount).
"""

CUSTOMIZE = """#!/system/bin/sh
# Sourced (not executed) by the module installer, so no exec bit is needed.
# Magisk 26+ and KernelSU metamodules bind-mount module files without syncing
# SELinux contexts. Force the jar to system_file so system_server can read it.

command -v ui_print >/dev/null 2>&1 && ui_print "  - Setting SELinux context on patched services.jar"

if [ -n "$MODPATH" ] && [ -f "$MODPATH/system/framework/services.jar" ]; then
  chcon u:object_r:system_file:s0 "$MODPATH/system/framework/services.jar" 2>/dev/null
  chmod 0644 "$MODPATH/system/framework/services.jar" 2>/dev/null
fi
"""


def build_module(patched_jar, out_zip):
    with zipfile.ZipFile(out_zip, "w") as z:
        for name, data, mode, comp in (
            ("module.prop", MODULE_PROP.encode(), 0o644, zipfile.ZIP_DEFLATED),
            ("customize.sh", CUSTOMIZE.encode(), 0o644, zipfile.ZIP_DEFLATED),
            ("system/framework/services.jar", open(patched_jar, "rb").read(),
             0o644, zipfile.ZIP_STORED),
        ):
            zi = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            zi.create_system = 3
            zi.external_attr = (mode & 0xFFFF) << 16
            zi.compress_type = comp
            z.writestr(zi, data)


def main():
    ap = argparse.ArgumentParser(description="Fix the app-zygote NPE in services.jar")
    ap.add_argument("jar", help="stock services.jar to patch")
    ap.add_argument("-o", "--out", help="output jar (default: <name>.patched.jar)")
    ap.add_argument("--module", metavar="ZIP", help="also write a flashable module zip")
    args = ap.parse_args()

    out = args.out or (os.path.splitext(args.jar)[0] + ".patched.jar")

    with zipfile.ZipFile(args.jar) as z:
        names = z.namelist()
        dex_names = [n for n in names if n.endswith(".dex")]
        if not dex_names:
            sys.exit("error: no .dex entries in this jar")
        print(f"[*] {args.jar}: {len(names)} entries, {len(dex_names)} dex")

        target = None
        for n in sorted(dex_names):
            dex = Dex(z.read(n), n)
            try:
                off, old_idx, new_idx = find_patch(dex)
            except LookupError as e:
                print(f"    {n}: {e}")
                continue
            print(f"[+] {n}: found call site at file offset {off:#x}")
            print(f"    method_idx {old_idx} -> {new_idx}")
            target = (n, dex, off, old_idx, new_idx)
            break

        if target is None:
            sys.exit("[!] could not locate the vulnerable call -- nothing patched")

        n, dex, off, old_idx, new_idx = target
        orig = dex.d
        patched, d = patch_dex(orig, off, old_idx, new_idx)
        diff = sum(1 for i in range(len(orig)) if orig[i] != patched[i])
        print(f"[+] dex size unchanged: {len(orig) == len(patched)} ({len(patched)} bytes)")
        print(f"[+] bytes changed: {diff} (1 method byte + 4 adler32 + 20 sha1)")

        repack(args.jar, out, {n: patched})
        print(f"[+] wrote {out} ({os.path.getsize(out)} bytes)")

        if args.module:
            build_module(out, args.module)
            print(f"[+] wrote module {args.module} ({os.path.getsize(args.module)} bytes)")

    print("\nNext steps:")
    print("  - Verify:  jadx -d out <patched.jar>  then check ProcessList.java")
    print("  - Deploy:  install the module zip (Magisk / KernelSU), reboot")
    print("  - Keep the stock jar so you can roll back")


if __name__ == "__main__":
    main()
