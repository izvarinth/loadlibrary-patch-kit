# Running Modern mpengine.dll (v1.1.25080+) with loadlibrary

This documents all changes needed to make Tavis Ormandy's [loadlibrary](https://github.com/taviso/loadlibrary)
run modern versions of Windows Defender's `mpengine.dll` (tested with v1.1.25080.5, ~14MB, 32-bit)
on Linux. The original project supported older engine versions; newer engines added VDM signature
verification and require many additional Windows API stubs.

## Quick Start

```bash
# Apply the source patch
git apply loadlibrary-modern-mpengine.patch

# Patch mpengine.dll to bypass VDM signature verification (see below)
python3 tools/patch_mpengine.py engine/mpengine.dll

# Build
make clean && make

# Scan a file
./mpclient scan/eicar.com
```

## What Was Broken and How It Was Fixed

### Problem 1: Engine Boot Hang (mpcache files)

**Symptom:** `__rsignal(RSIG_BOOTENGINE)` would hang indefinitely.

**Root cause:** `open_special_if_missing()` in `Files.c` created empty 0-byte `mpcache-*.bin`
files when the engine tried to open them. The engine would read these empty files, find no valid
header, and throw C++ exceptions leading to error code 0x8001.

**Fix:** Removed `mpcache-` from the file creation pattern. Only `mpenginetestlicense.dat` is
auto-created (the engine handles empty license files gracefully). The engine treats missing cache
files as "no cache available" and skips cache initialization.

**File:** `peloader/winapi/Files.c` - `open_special_if_missing()`

---

### Problem 2: VDM Signature Verification Failure (0xa005)

**Symptom:** `RSIG_BOOTENGINE` returned error code 0xa005 ("signature check failed").

**Root cause:** Modern mpengine.dll versions verify the Authenticode signatures of VDM files
(virus definition modules) using internal, compiled-in cryptographic routines. These checks
don't call external BCrypt/CryptoAPI functions, so they can't be intercepted via API stubs.

**Fix:** Binary patch 3 conditional jump instructions in `mpengine.dll` to always take the
"signature valid" code path:

| File Offset | VA Address   | Original | Patched | Instruction Change |
|-------------|-------------|----------|---------|-------------------|
| 0x2CEE8E    | 0x102CFA8E  | 0x75 (jne) | 0xEB (jmp) | Skip 0x4DC->0xa005 error mapping |
| 0x2D5C04    | 0x102D6804  | 0x74 (je)  | 0xEB (jmp) | Always take success path |
| 0x2DC162    | 0x102DCD62  | 0x7C (jl)  | 0xEB (jmp) | Always trust certificate chain |

**Important:** These offsets are specific to mpengine.dll v1.1.25080.5. Different versions will
have different offsets. To find them in a new version, search for `mov eax, 0xa005` (bytes
`B8 05 A0 00 00`) and examine the conditional jumps preceding each instance.

To apply manually:
```bash
cp engine/mpengine.dll engine/mpengine.dll.orig
printf '\xEB' | dd of=engine/mpengine.dll bs=1 seek=$((0x2CEE8E)) conv=notrunc
printf '\xEB' | dd of=engine/mpengine.dll bs=1 seek=$((0x2D5C04)) conv=notrunc
printf '\xEB' | dd of=engine/mpengine.dll bs=1 seek=$((0x2DC162)) conv=notrunc
```

---

### Problem 3: SEH Chain Corruption During Scan (crash on C++ exception)

**Symptom:** After boot succeeded, `RSIG_SCAN_STREAMBUFFER` would crash with a segfault
during C++ exception handling. The first two C++ exceptions were caught properly, but the
third had a corrupt SEH chain (Prev pointer pointing to heap instead of stack).

**Root cause:** In `RtlUnwind()`, when the TargetFrame was reached, `setcontext()` was called
to restore the caller's context without first removing the TargetFrame from the SEH chain
(`fs:0`). After the exception handler's catch block completed, `fs:0` still referenced the
old frame address. When the stack was reused by subsequent function calls, the stale SEH frame
data was overwritten with unrelated data, corrupting the chain.

**Fix:** Added `asm("mov %[list], %%fs:0" :: [list] "r"(ExceptionList->prev))` before
`setcontext()` in `RtlUnwind()` to properly unlink the target frame from the SEH chain.

**File:** `peloader/winapi/Exception.c` - `RtlUnwind()`

Additionally, `RaiseException()` was changed to return NULL instead of calling `__debugbreak()`
for unhandled exceptions, since some C++ exceptions during normal engine operation are expected
to go unhandled (the C++ runtime handles them via `std::terminate` or similar).

---

### Problem 4: Missing Windows API Stubs

The modern engine requires many API functions that the original loadlibrary didn't implement.
All new stubs are registered via `DECLARE_CRT_EXPORT()`.

#### Cryptography APIs (`peloader/winapi/Crypt.c`)

15 BCrypt functions:
- `BCryptOpenAlgorithmProvider`, `BCryptCloseAlgorithmProvider`
- `BCryptGetProperty`, `BCryptSetProperty`
- `BCryptCreateHash`, `BCryptHashData`, `BCryptFinishHash`, `BCryptDestroyHash`
- `BCryptGenRandom` (reads from `/dev/urandom`)
- `BCryptImportKeyPair`, `BCryptDestroyKey`, `BCryptVerifySignature`
- `BCryptImportKey`, `BCryptDecrypt`, `BCryptEncrypt`

CryptoAPI functions:
- `CryptAcquireContextW`, `CryptImportPublicKeyInfo`, `CryptVerifySignatureW`
- `CryptReleaseContext`, `CryptDestroyKey`

Certificate Store functions:
- `CertOpenStore`, `CertCloseStore`, `CertEnumCertificatesInStore`
- `CertFindCertificateInStore` (with real Microsoft Root CA and Intermediate CA certificates)
- `CertFreeCertificateContext`, `CertGetCertificateChain`, `CertFreeCertificateChain`
- `CertVerifyCertificateChainPolicy`, `CertGetNameStringW`

The certificate store contains real DER-encoded Microsoft certificates:
- **Root:** Microsoft Root Certificate Authority 2010 (`peloader/winapi/Crypt.c`)
- **Intermediate:** Microsoft Windows Code Signing PCA 2024 (`peloader/winapi/intermediacert.h`)

#### WinTrust / Catalog APIs (`peloader/winapi/WinTrust.c`)

Major rewrite from stub to functional implementations:
- `WinVerifyTrust` - returns success
- `CryptCATAdminAcquireContext2`, `CryptCATAdminCalcHashFromFileHandle2`
- `CryptCATAdminEnumCatalogFromHash`, `CryptCATAdminReleaseCatalogContext`
- `CryptCATAdminReleaseContext`, `CryptCATCatalogInfoFromContext`
- `CryptSIPRetrieveSubjectGuid`

#### Locale APIs (`peloader/winapi/Locale.c`)

- `EnumSystemLocalesEx`, `GetDateFormatEx`, `GetTimeFormatEx`
- `GetUserDefaultLocaleName`, `IsValidLocaleName`, `LCIDToLocaleName`

All return en-US locale data.

#### Environment / Path APIs (`peloader/winapi/Environment.c`)

- `ExpandEnvironmentStringsW` - complete rewrite to handle compound paths like
  `%ProgramData%\Microsoft\Windows Defender\...`
- Supports: `%ProgramFiles%`, `%ProgramData%`, `%windir%`, `%SystemRoot%`,
  `%AllUsersProfile%`, `%CommonProgramFiles%`, `%PATH%`

#### File I/O (`peloader/winapi/Files.c`)

- `normalize_winpath()` - proper Windows-to-POSIX path conversion
  (handles `\\?\`, `\\.\`, drive letters, backslash translation)
- `ResolveCasePath()` - case-insensitive file lookup for Linux
- `open_special_if_missing()` - selective file creation
- `QueryDosDevice` - returns `\Device\HarddiskVolume1` for drive letters

#### Process/Thread (`peloader/winapi/ProcessThreads.c`)

- `TryAcquireSRWLockExclusive` - always returns TRUE (single-threaded)

#### Module Loading (`peloader/winapi/LoadLibrary.c`)

- `GetModuleFileNameA` - returns a realistic path for mpengine.dll instead of
  `C:\dummy\fakename.exe`

#### Additional Stubs (`peloader/winapi/Missing.c`)

New file with ~1200 lines of additional stubs for NTDLL, kernel32, advapi32, etc.
functions that the engine resolves via `GetProcAddress()`.

---

### Problem 5: mpclient.c Infrastructure Improvements

- **Crash handler:** SIGSEGV/SIGBUS/SIGABRT/SIGTRAP handler prints register state (EIP, ESP,
  EBP, etc.) for debugging crashes inside mpengine.dll
- **Unbuffered stderr:** `setvbuf(stderr, NULL, _IONBF, 0)` ensures debug output survives crashes
- **File descriptor limit:** Increased from 32 to 256 (`RLIMIT_NOFILE`)
- **`CallRsignal()` wrapper:** Adds optional timeout (`MPCLIENT_RSIG_TIMEOUT` env var) and
  tracing (`MPCLIENT_TRACE_RSIG=1` env var)
- **`LogDirListing()`:** Logs engine directory contents at startup for diagnostics

---

## File Inventory

### Modified Files (from upstream)

| File | Changes |
|------|---------|
| `Makefile` | NDEBUG flag in CPPFLAGS |
| `mpclient.c` | Crash handler, CallRsignal wrapper, LogDirListing, unbuffered stderr |
| `peloader/pe_linker.c` | Minor fix |
| `peloader/winapi/Crypt.c` | BCrypt, CryptoAPI, certificate store (~274 lines added) |
| `peloader/winapi/Environment.c` | ExpandEnvironmentStringsW rewrite (~114 lines changed) |
| `peloader/winapi/Exception.c` | RtlUnwind fs:0 fix, RaiseException graceful unhandled |
| `peloader/winapi/Files.c` | Path normalization, case-insensitive lookup (~243 lines added) |
| `peloader/winapi/LoadLibrary.c` | GetModuleFileNameA proper path |
| `peloader/winapi/Locale.c` | 6 new locale function stubs (~64 lines added) |
| `peloader/winapi/ProcessThreads.c` | TryAcquireSRWLockExclusive |
| `peloader/winapi/WinTrust.c` | Complete rewrite with catalog/trust APIs (~684 lines added) |

### New Files

| File | Purpose |
|------|---------|
| `peloader/winapi/intermediacert.h` | Microsoft intermediate CA certificate (DER, 1729 bytes) |
| `peloader/winapi/Missing.c` | Additional Windows API stubs (~1188 lines) |

### Binary Patch

| File | Purpose |
|------|---------|
| `engine/mpengine.dll` | 3 bytes changed to bypass VDM signature verification |

---

## Debugging Tips

### Enable debug logging
```bash
# Remove -DNDEBUG from both Makefiles:
# Makefile:      CPPFLAGS=-D_GNU_SOURCE -I. -Iintercept -Ipeloader
# peloader/Makefile: CPPFLAGS=-D_GNU_SOURCE -I.
make clean && make
./mpclient scan/eicar.com 2>debug.log
```

### Enable rsignal tracing
```bash
MPCLIENT_TRACE_RSIG=1 ./mpclient scan/file.exe
```

### Set rsignal timeout (seconds)
```bash
MPCLIENT_RSIG_TIMEOUT=30 ./mpclient scan/file.exe
```

### Find 0xa005 patch points in a new mpengine.dll version
```bash
# Search for mov eax, 0xa005
grep -c -P '\xB8\x05\xA0\x00\x00' engine/mpengine.dll
objdump -d -M intel engine/mpengine.dll | grep -B5 'mov.*eax,0xa005'
```

---

## Tested Results

Engine version: 1.1.25080.5 with VDM signatures from May 2025.

| Test File | Detection |
|-----------|-----------|
| `eicar.com` (EICAR standard test) | Virus:DOS/EICAR_Test_File |
| `amsi_test.txt` (AMSI test string) | Virus:Win32/MpTest!amsi |
| `shellcode_test.bin` (x86 shellcode) | TEL:VatetCrypt.A |
| `invoke_mimikatz.ps1` | Scanned, Base64 extracted, no detection |
| `powershell_dropper.ps1` | Scanned, EmbeddedEnc extracted, no detection |
| `macro_test.doc.vba` | Scanned, no detection |
| `suspicious_pe.exe` | Scanned, no detection |

The engine successfully boots, loads all 4 VDM files (MPAVDLTA, MPAVBASE, MPASDLTA, MPASBASE),
and performs signature-based scanning with real Windows Defender detections.
