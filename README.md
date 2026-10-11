# Fixing blank Chromium pages on ported ROMs — patching `services.jar`

A guide for ROM porters.

**Applies to:** OEM builds (Xiaomi/HyperOS, ColorOS, …) ported to another device where
**every Chromium browser shows blank pages**, including internal pages like
`chrome://flags`. Chrome, Brave, Edge, Vivaldi, WebView-based apps — all affected.

**The fix:** one byte in `services.jar` → `classes.dex`. Identical to the upstream
AOSP change `I093c5ef5aef` (LineageOS 496512).

---

## TL;DR

```bash
# 1. Patch
python3 fix_appzygote.py services.jar --module chromefix-module.zip

# 2. Verify
jadx -d out services.patched.jar
grep getOrCreate out/sources/com/android/server/am/ProcessList.java

# 3. Deploy the module zip (Magisk / KernelSU / metamodule), reboot
```

Then **read §7.2 — the SELinux trap.** Skipping it bootloops the device.

---

## 1. Symptom

- Chromium renderers never spawn. `ps -A | grep com.android.chrome` shows only the
  main process and `:privileged_process0` — no `:sandboxed_process0`.
- No app zygote is ever created (no `com.android.chrome_zygote_native`).
- Every page is blank, including `chrome://flags` (which needs no network).
- Non-Chromium apps work fine.

Confirm it in logcat:

```bash
adb logcat -d | grep -E "createAppZygoteForProcessIfNeeded|Failure starting process com.android.chrome"
```

You will see:

```
Failure starting process com.android.chrome:sandboxed_process0:...:0
java.lang.NullPointerException: Attempt to read from field
  'int com.android.server.am.ProcessList$IsolatedUidRange.mFirstUid'
  on a null object reference
  at com.android.server.am.ProcessList.createAppZygoteForProcessIfNeeded(ProcessList.java:2737)
```

---

## 2. Root cause

Affected OEM builds ship a modified `ProcessList.createAppZygoteForProcessIfNeeded()`
with a safesetid fast-path and a fallback:

```java
if (Flags.useSafesetidUidPolicy2()
        && UidTransitionPolicy.isEnabled()
        && getUidTransitionPolicy() != null) {
    // fast path: global app-isolated UID range (90000..98999)
    firstUid = UserHandle.getUid(userId, this.mGlobalAppIsolatedUids.mFirstUid);
    lastUid  = UserHandle.getUid(userId, this.mGlobalAppIsolatedUids.mLastUid);
    getUidTransitionPolicy().disallowAllUidTransitionsFrom(uid);
} else {
    // fallback path
    IsolatedUidRange uidRange = this.mAppIsolatedUidRangeAllocator
            .getIsolatedUidRangeLocked(app.info.processName,
                                       app.getHostingRecord().getDefiningUid());
    int firstUid3 = UserHandle.getUid(userId, uidRange.mFirstUid);   // <-- NPE
    lastUid       = UserHandle.getUid(userId, uidRange.mLastUid);
}
```

Why it breaks **after porting** (not on the original device):

1. `use_safesetid_uid_policy2` is `true` in DeviceConfig, and the safesetid policy
   file exists, so the framework *intends* to take the fast path.
2. On the port, `/sys/kernel/security/safesetid/uid_allowlist_policy` is
   **unwritable** (wrong SELinux label from a mismatched `sepolicy`/kernel), so
   `UidTransitionPolicy` fails to initialise and `getUidTransitionPolicy()` returns
   **null**.
3. Because of the third condition, the guard fails → the `else` branch runs.
4. In that branch the per-app `IsolatedUidRangeAllocator` is **empty** — only the
   fast path would have allocated ranges — so `getIsolatedUidRangeLocked()` returns
   `null`, and the very next line dereferences it → `system_server` crashes.
5. If repeat app-zygote requests keep killing `system_server`, you may also see the
   device hot-reboot or land in a partial boot.

**The fix** is to call `getOrCreateIsolatedUidRangeLocked()` in that branch. It has
the **same class, same name shape, same prototype** as the getter but allocates the
range when missing — which is exactly what AOSP/LineageOS did:

```java
IsolatedUidRange uidRange = this.mAppIsolatedUidRangeAllocator
        .getOrCreateIsolatedUidRangeLocked(app.info.processName,
                                          app.getHostingRecord().getDefiningUid());
```

Because the prototype is identical, this is a **one-byte `method_idx` change** in a
DEX `invoke-virtual` instruction. No new methods, no size change, no recompilation
concerns.

---

## 3. Why the "obvious" fixes fail (save yourself the time)

| Attempt | Result |
|---|---|
| `adb shell su -c "device_config put backstage_power com.android.server.am.use_safesetid_uid_policy2 false"` | `SecurityException: Permission denial for flag ... must add flag to the allowlist`. Protected at runtime. |
| Setting it from a root/uid-1000 shell | Writes are ignored; the flag stays `true`. |
| Making the safesetid policy file writable (tmpfs shadow + `chcon`) and writing rules | Works only until reboot. `ksud` live `sepolicy` patches don't survive; the node reverts and the NPE returns. Also risks breaking `init`/`init`-label propagation. |
| `--no-sandbox` / `--single-process` Chrome flags | Irrelevant — the crash happens in `system_server` *before* Chrome starts. Command-line flags can't reach it. |

The SELinux/safesetid rabbit hole is deep and fragile. **Patch the jar instead.**

---

## 4. What you need

- Python 3 (no third-party modules)
- The ROM's `services.jar` (pull it — see §6.1)
- Optional: [jadx](https://github.com/skylot/jadx) to verify the decompiled result
- Optional: `zip`/`unzip` if you hand-build the module

`fix_appzygote.py` (in this kit) does everything in §6 automatically.

---

## 5. Quick method

```bash
python3 fix_appzygote.py services.jar                 # → services.patched.jar
python3 fix_appzygote.py services.jar --module out.zip  # + flashable module zip
```

It will:

- scan every `classes*.dex` for `Lcom/android/server/am/ProcessList;`
- locate `createAppZygoteForProcessIfNeeded`
- find the `invoke-virtual` of `getIsolatedUidRangeLocked` inside it
- find `getOrCreateIsolatedUidRangeLocked` with the **matching prototype**
- flip the method index, recompute Adler-32 + SHA-1
- rebuild the jar preserving all entries, order and compression

It refuses to touch an already-fixed or non-affected jar, so it's safe to re-run.

Skip to **§7** to deploy, or read §6 to understand / verify / hand-roll it.

---

## 6. Manual method

### 6.1 Pull `services.jar`

```bash
adb shell su -c "cp /system/framework/services.jar /data/local/tmp/"
adb pull /data/local/tmp/services.jar
```

> `adb pull` runs as the `shell` user and **cannot** read `/data/adb` or `/system`
> directly — always stage through `/data/local/tmp` first.

### 6.2 Find the call site

You need three things:

1. The dex that contains `Lcom/android/server/am/ProcessList;`.
2. The bytecode of `createAppZygoteForProcessIfNeeded`.
3. The offset of the `invoke-virtual` that calls
   `Lcom/android/server/am/ProcessList$IsolatedUidRangeAllocator;.getIsolatedUidRangeLocked`.

With jadx, get the picture:

```bash
unzip -o services.jar 'classes*.dex' -d dex/
jadx -d out dex/classes.dex
grep -n "getOrCreateIsolatedUidRangeLocked\|getIsolatedUidRangeLocked" \
     out/sources/com/android/server/am/ProcessList.java
```

The `else` branch in `createAppZygoteForProcessIfNeeded` is the one to change.

`invoke-virtual` is opcode `0x6e`, format **35c**:

```
byte 0   : opcode 0x6e
byte 1   : A/G   (register count + 5th register)
bytes 2-3: BBBB  = method_idx   <-- little-endian, this is what you change
bytes 4-5: registers C..F
```

So at the instruction offset: `6e 30 <lo> <hi> …`. Read the 2 bytes at +2 for the
current `method_idx`.

### 6.3 Patch the byte

- `old_idx` = index of `getIsolatedUidRangeLocked(IsolatedUidRange, String, int)`
- `new_idx` = index of `getOrCreateIsolatedUidRangeLocked(IsolatedUidRange, String, int)`

**Verify the two prototypes match exactly** (shorty + full parameter list) before
changing anything. In practice OEMs place them adjacently, so it's often
`old_idx + 1`.

Write the new index little-endian at instruction offset +2. Nothing else in the
bytecode moves.

### 6.4 Fix the header

The DEX header validates its own content — you must recompute both fields or ART
will reject the file:

| Field | Offset | Value |
|---|---|---|
| `checksum` | `0x08` | Adler-32 of `bytes[0x0C:]`, little-endian |
| `signature` | `0x0C` (20 bytes) | SHA-1 of `bytes[0x20:]` |

Order matters: compute SHA-1 first, then Adler-32.

```python
import hashlib, zlib
d[0x0C:0x20] = hashlib.sha1(bytes(d[0x20:])).digest()
d[0x08:0x0C] = (zlib.adler32(bytes(d[0x0C:])) & 0xFFFFFFFF).to_bytes(4, "little")
```

### 6.5 Repack

Put the patched `classes.dex` back into a copy of the jar. **Keep every entry name,
order and compression method.** Android's ART reads system jars positionally.

- `classes.dex` in `services.jar` is normally **Stored** (uncompressed). Preserve
  that.
- Only `classes.dex` should differ; all other entries must be byte-identical.

A rebuilt jar is typically a few hundred bytes smaller/larger because your zip
library compresses the small `.uau`/`.xml`/`MANIFEST.MF` entries slightly
differently. **That is fine** — only the script-entry contents matter. Do not panic
about the size delta; DO verify entry-by-entry that nothing else changed.

### 6.6 Verify

```bash
jadx -d out services.patched.jar
grep -n "getOrCreateIsolatedUidRangeLocked" out/sources/com/android/server/am/ProcessList.java
```

Expected: `createAppZygoteForProcessIfNeeded` now calls
`getOrCreateIsolatedUidRangeLocked`, and `removeProcessFromAppZygoteLocked`
**still** calls `getIsolatedUidRangeLocked` (leave that one alone — the upstream
change only touches the create path).

Sanity checks:

- DEX file size is **unchanged**.
- Only 1 method byte + 4 checksum bytes + 20 signature bytes differ
  (25 total; occasionally 24 if one checksum byte coincidentally matches).
- `unzip -t services.patched.jar` → no errors.

---

## 7. Deploy the patched jar

`services.jar` lives on the read-only `/system` partition (often EROFS). You must
overlay it at boot with a Magisk/KernelSU module. There is **no** `.odex`/`.vdex`/
`boot.art` to worry about for `services.jar`; ART recompiles on first boot.

### 7.1 Module layout

Module zip (flat layout — **no** top-level folder):

```
module.prop
customize.sh
system/framework/services.jar     <-- the patched jar
```

`module.prop`:

```
id=chromefix
name=Chromium app-zygote NPE fix
version=v2
versionCode=2
author=you
description=Fixes blank Chromium pages (app-zygote NPE).
```

Do **not** create a `skip_mount` file. The `system/` folder is mounted
automatically by Magisk's magic mount, KernelSU's built-in mount, or a KernelSU
metamodule's `metamount.sh`.

### 7.2 ⚠ The SELinux labeling trap — read this

**This is the single most common way porters bootloop the device.**

Mount engines **bind-mount** the module file over the target. A bind mount does
**not** change the file's SELinux label. So
`/system/framework/services.jar` ends up carrying whatever label the file has under
`/data/adb/...` — typically `u:object_r:adb_data_file:s0` —
instead of the required `u:object_r:system_file:s0`.

Result: `system_server` cannot read its own classpath and you get a bootloop with:

```
ClassNotFoundException: com.android.server.SystemServer
```

Aggravating factors:

- **Magisk 26+** deliberately does *not* synchronise contexts onto module files
  (see Magisk issue #6859). The maintainer calls the old sync behaviour
  *"indeterminate internal behaviour… not safe to rely on."* On Magisk the wrong
  label is the *default* outcome.
- **KernelSU metamodules** run `metamount.sh` **after** all `post-fs-data.sh`
  scripts, so a boot-time script in your module **cannot** fix the label in time.
- **`ksud` ignores Unix permission bits** when extracting a module zip — a
  `post-fs-data.sh` in your zip lands as `0644` and never runs.

**The correct fix: label the file at install time**, from `customize.sh`, which the
installer *sources* (so no exec bit is needed) and which runs **before** any mount:

`customize.sh`:

```sh
#!/system/bin/sh
command -v ui_print >/dev/null 2>&1 && ui_print "  - Setting SELinux context"

if [ -n "$MODPATH" ] && [ -f "$MODPATH/system/framework/services.jar" ]; then
  chcon u:object_r:system_file:s0 "$MODPATH/system/framework/services.jar" 2>/dev/null
  chmod 0644 "$MODPATH/system/framework/services.jar" 2>/dev/null
fi
```

Rules of thumb:

- Prefer `customize.sh` over `post-fs-data.sh` for anything install-time.
- Never rely on `post-fs-data.sh` for this fix.
- Install-time `chcon` survives into the mounted file, because the mount shares the
  inode.

### 7.3 Deploying

```bash
adb push chromefix-module.zip /data/local/tmp/
adb shell su -c "ksud module install /data/local/tmp/chromefix-module.zip"
# Magisk:  adb shell su -c "magisk --install-module /data/local/tmp/chromefix-module.zip"
# then reboot
```

If you use a KernelSU **metamodule** (KernelSU-Next v3 removes the built-in mount
and requires one, e.g. `meta-magic_mount` / `meta-overlayfs`), install it too. Prefer
a **magic-mount** metamodule over an overlayfs one — overlayfs layering is more
likely to drop the file's context.

**Never install two modules with the same `id`.** The KernelSU manager keys its
module list by `id`; duplicates throw
`IllegalArgumentException: Key "..." was already used` and crash the manager on
every render.

---

## 8. Verify on device

```bash
# the overlay is in place and labelled correctly
adb shell su -c "ls -laZ /system/framework/services.jar"
# expect: ... u:object_r:system_file:s0 ... <patched size>

adb shell su -c "mount | grep services.jar"

# boot a browser and look for a renderer
adb logcat -c
adb shell am force-stop com.android.chrome
adb shell input keyevent KEYCODE_WAKEUP; adb shell wm dismiss-keyguard
adb shell am start -a android.intent.action.VIEW -d "chrome://flags" \
  -n com.android.chrome/com.google.android.apps.chrome.Main
sleep 10
adb shell su -c "ps -A -o NAME | grep com.android.chrome"
```

Success looks like:

```
com.android.chrome
com.android.chrome_zygote_native                      <-- app zygote exists
com.android.chrome:sandboxed_process0:...:0           <-- renderer(s)
com.android.chrome:sandboxed_process0:...:1
com.android.chrome:privileged_process0
```

And this must print **nothing**:

```bash
adb logcat -d | grep -E "createAppZygoteForProcessIfNeeded|Failure starting process com.android.chrome"
```

---

## 9. Rollback

If it goes wrong:

```bash
adb shell su -c "touch /data/adb/modules/<id>/disable"   # works even without system_server
adb reboot
```

Or remove the module directory entirely. Keep the **stock** `services.jar` — you
must re-patch against the stock jar, never against your own patched output.

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ClassNotFoundException: com.android.server.SystemServer` / bootloop | Wrong SELinux label on the mounted jar | §7.2 — `chcon system_file` in `customize.sh` |
| Bootloop, `unzip`/ART rejects the jar | Rebuilt zip is malformed | Preserve entry names/order/compression; `unzip -t` it |
| Bootloop, checksum error | Forgot to recompute Adler-32 / SHA-1 | §6.4; compute SHA-1 **then** Adler-32 |
| `Fix: nothing patched` from the tool | Already fixed, or `ProcessList` in another dex | Check every `classes*.dex`; confirm the ROM is OEM-descended |
| Chrome still blank after boot | Module not mounted (metamodule missing on KSU-Next v3) | Install a metamodule, or check `mount \| grep services.jar` |
| Manager app crashes on open | Two modules sharing an `id` | Remove the duplicate |
| Renderer still missing, different error | safesetid genuinely denying `setuid` for app zygotes | Out of scope for this patch — kernel/sepolicy issue |

---

## 11. DEX format gotchas (if you write your own tool)

These bite everyone once:

1. **`endian_tag` sits at `0x28`.** Header layout is
   `magic(8) · checksum(4) · signature(20) · file_size(4) · header_size(4) ·
   endian_tag(4) · link_size(4) · link_off(4) · map_off(4) · string_ids…`
   Forget it and every subsequent offset is off by 4 → garbage strings and
   `IndexError`.
2. **`type_list` entries are `ushort`, not `uint`.** A `proto_id`'s
   `parameters_off` points to `uint size; ushort type_idx[size];`, 4-byte aligned.
   Reading them as 4-byte ints yields nonsense parameter types.
3. **`string_data_item` starts with a `uleb128` UTF-16 length** before the MUTF-8
   bytes; the terminator is a `0x00`. Scan for the null, not a fixed length.
4. **Instruction lengths are not uniform.** Decode using the opcode width table;
   don't scan every 16-bit word for `0x6e`, or you'll match bytes inside literals.
5. **`invoke-virtual` is `0x6e`** (`/range` is `0x74`), and the `method_idx` is the
   16-bit little-endian value at instruction offset **+2**.
6. **Class data is ULEB-diff encoded**: `method_idx` values are stored as deltas
   from the previous method in the same direct/virtual list.
7. **Offsets are per-build.** Never reuse an offset or method index from another
   `services.jar`, even a sibling firmware of the same model. Re-derive every time.

---

## 12. Reference

- Upstream fix: AOSP Change-Id `I093c5ef5aef3937ec96ed1c9e43c54cb3808a418`
  (LineageOS Gerrit 496512 — `ProcessList: use getOrCreateIsolatedUidRangeLocked`).
- Magisk issue #6859 — module files do not inherit the replaced file's SELinux
  context on Magisk 26+.
- KernelSU metamodule docs — `metamount.sh` runs *after* `post-fs-data.sh`.
- Android DEX format: `dex-format` (checksum / signature / `type_list` / 35c).

---

*Kit contents:* `fix_appzygote.py` (auto-patcher, no dependencies) + this guide.
