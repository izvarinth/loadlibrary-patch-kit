#!/usr/bin/env python3
"""
Patch mpengine.dll to bypass VDM signature verification.

These patches change conditional jumps to unconditional jumps at the three
locations where the engine checks VDM Authenticode signatures and returns
error 0xa005 on failure.

Usage:
    python3 tools/patch_mpengine.py engine/mpengine.dll

NOTE: Offsets are for mpengine.dll v1.1.25080.5 (~14MB, 32-bit PE).
      For other versions, run with --find-offsets to search for patch points.
"""

import sys
import struct
import shutil
import os

# Patches for v1.1.25080.5
# Each tuple: (file_offset, original_byte, patched_byte, description)
PATCHES_V1_1_25080 = [
    (0x2CEE8E, 0x75, 0xEB, "jne->jmp: skip 0x4DC->0xa005 error mapping"),
    (0x2D5C04, 0x74, 0xEB, "je->jmp: always take success path (esi==0)"),
    (0x2DC162, 0x7C, 0xEB, "jl->jmp: always trust certificate chain"),
]

# The byte sequence for "mov eax, 0xa005" which marks signature check failures
MOV_EAX_A005 = b'\xB8\x05\xA0\x00\x00'


def find_a005_locations(data):
    """Find all 'mov eax, 0xa005' instructions in the binary."""
    locations = []
    start = 0
    while True:
        idx = data.find(MOV_EAX_A005, start)
        if idx == -1:
            break
        locations.append(idx)
        start = idx + 1
    return locations


def apply_patches(filepath, patches):
    """Apply binary patches to the file."""
    # Backup first
    backup = filepath + '.orig'
    if not os.path.exists(backup):
        shutil.copy2(filepath, backup)
        print(f"Backup saved to {backup}")

    with open(filepath, 'r+b') as f:
        for offset, orig, new, desc in patches:
            f.seek(offset)
            current = f.read(1)[0]
            if current == new:
                print(f"  [SKIP] Offset 0x{offset:06X}: already patched ({desc})")
                continue
            if current != orig:
                print(f"  [WARN] Offset 0x{offset:06X}: expected 0x{orig:02X}, found 0x{current:02X} - wrong version?")
                continue
            f.seek(offset)
            f.write(bytes([new]))
            print(f"  [OK]   Offset 0x{offset:06X}: 0x{orig:02X} -> 0x{new:02X} ({desc})")

    print("Done.")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <mpengine.dll> [--find-offsets]")
        sys.exit(1)

    filepath = sys.argv[1]
    find_only = '--find-offsets' in sys.argv

    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"File: {filepath} ({len(data)} bytes)")

    if find_only:
        print(f"\nSearching for 'mov eax, 0xa005' (signature check failure points)...")
        locations = find_a005_locations(data)
        if not locations:
            print("No instances found - this binary may not have signature checks.")
        else:
            print(f"Found {len(locations)} instance(s):")
            for loc in locations:
                va = 0x10000000 + loc - 0x400 + 0x1000
                # Show surrounding bytes for context
                context_start = max(0, loc - 16)
                context = data[context_start:loc + 8]
                hexdump = ' '.join(f'{b:02X}' for b in context)
                print(f"  File offset 0x{loc:06X} (VA 0x{va:08X})")
                print(f"    Context: ...{hexdump}...")
                # Look for conditional jump in the preceding ~10 bytes
                for i in range(min(10, loc), 0, -1):
                    b = data[loc - i]
                    if b in (0x74, 0x75, 0x7C, 0x7D, 0x7E, 0x7F, 0x72, 0x73, 0x76, 0x77):
                        jmp_names = {0x74: 'je', 0x75: 'jne', 0x7C: 'jl', 0x7D: 'jge',
                                     0x7E: 'jle', 0x7F: 'jg', 0x72: 'jb', 0x73: 'jae',
                                     0x76: 'jbe', 0x77: 'ja'}
                        name = jmp_names.get(b, f'j?? (0x{b:02X})')
                        patch_off = loc - i
                        print(f"    Candidate patch: offset 0x{patch_off:06X}, {name} (0x{b:02X}) -> jmp (0xEB)")
        sys.exit(0)

    # Apply known patches
    print(f"\nApplying signature verification bypass patches (v1.1.25080.5)...")

    # Verify this looks like the right version
    locations = find_a005_locations(data)
    if len(locations) != 3:
        print(f"WARNING: Expected 3 'mov eax, 0xa005' locations, found {len(locations)}.")
        print("This may be a different engine version. Use --find-offsets to locate patch points.")
        if not locations:
            sys.exit(1)

    apply_patches(filepath, PATCHES_V1_1_25080)


if __name__ == '__main__':
    main()
