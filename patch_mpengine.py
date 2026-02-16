#!/usr/bin/env python3
"""
Patch mpengine.dll to bypass VDM signature verification.

Automatically discovers patch sites by finding 'mov eax, 0xa005' (the
signature verification error code) and identifying the guarding conditional
jump that, when made unconditional, skips the error path.

Works across mpengine.dll versions without hardcoded offsets.

Usage:
    python3 patch_mpengine.py engine/mpengine.dll
    python3 patch_mpengine.py engine/mpengine.dll --find-offsets
"""

import struct
import shutil
import os
import sys

# The byte sequence for "mov eax, 0xa005" which marks signature check failures
MOV_EAX_A005 = b"\xB8\x05\xA0\x00\x00"
MOV_EAX_A005_LEN = 5

# How far back from each anchor to scan for the guarding conditional jump
MAX_SCAN_DISTANCE = 80

# Short conditional jump opcodes (0x70-0x7F)
SHORT_JCC_RANGE = range(0x70, 0x80)

# Near conditional jump second byte (0x0F 0x80-0x8F)
NEAR_JCC_PREFIX = 0x0F
NEAR_JCC_RANGE = range(0x80, 0x90)

JCC_NAMES = {
    0x70: "jo",
    0x71: "jno",
    0x72: "jb",
    0x73: "jae",
    0x74: "je",
    0x75: "jne",
    0x76: "jbe",
    0x77: "ja",
    0x78: "js",
    0x79: "jns",
    0x7A: "jp",
    0x7B: "jnp",
    0x7C: "jl",
    0x7D: "jge",
    0x7E: "jle",
    0x7F: "jg",
}


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


def decode_short_jcc(data, pos):
    """Decode a short conditional jump at pos. Returns (condition, target)."""
    opcode = data[pos]
    if opcode not in SHORT_JCC_RANGE:
        return None
    disp = data[pos + 1]
    if disp > 127:
        disp -= 256
    target = pos + 2 + disp
    return opcode, target


def decode_near_jcc(data, pos):
    """Decode a near conditional jump at pos. Returns (condition, target)."""
    if pos + 5 >= len(data):
        return None
    if data[pos] != NEAR_JCC_PREFIX:
        return None
    second = data[pos + 1]
    if second not in NEAR_JCC_RANGE:
        return None
    disp = struct.unpack_from("<i", data, pos + 2)[0]
    target = pos + 6 + disp
    condition = second - 0x10  # 0x80->0x70, maps to same condition as short
    return condition, target


def _select_best_candidate(candidates):
    """Select the best patch candidate from a list of possibilities.

    When multiple conditional jumps skip past the error instruction,
    uses target clustering to pick the right one:
    - If 2+ candidates share the same jump target, they form a guard
      cluster for the same error block. Pick the outermost (furthest
      from anchor) in the largest cluster.
    - If all candidates have unique targets, pick the one closest to
      the anchor (most conservative, least risk of crossing basic
      block boundaries).
    """
    if len(candidates) == 1:
        return candidates[0]

    # Group candidates by jump target
    target_groups = {}
    for c in candidates:
        target_groups.setdefault(c["target"], []).append(c)

    # Find the largest cluster
    largest_group = max(target_groups.values(), key=len)

    if len(largest_group) > 1:
        # Multiple candidates jump to the same target — take the outermost
        return max(largest_group, key=lambda c: c["distance"])

    # All unique targets — take the closest to the anchor
    return min(candidates, key=lambda c: c["distance"])


def _is_fall_through_guard(data, pos, insn_len, anchor, target):
    """Check if a conditional jump is a fall-through guard for the error.

    Pattern B: the conditional jump ends immediately at the anchor, so its
    fall-through path goes directly to 'mov eax, 0xa005'. The jump target
    goes elsewhere (skipping the error). Making it unconditional prevents
    the fall-through, so the error code is never reached.

    This catches cases like: cmp ebx, 0x4DC; jne <backward>; mov eax, 0xa005
    where the jne jumps away from the error and fall-through sets it.
    """
    jump_end = pos + insn_len
    if jump_end != anchor:
        return False
    # Target must not land within the error instruction itself
    if anchor <= target < anchor + MOV_EAX_A005_LEN:
        return False
    return True


def discover_patch_sites(data):
    """Auto-discover VDM signature bypass patch sites.

    For each 'mov eax, 0xa005' anchor, finds the guarding conditional jump
    using two patterns:

    Pattern A (forward skip): conditional jump whose target lands past the
    error instruction. The jump skips over the error when taken.

    Pattern B (fall-through guard): conditional jump that ends immediately
    at the anchor, so its fall-through is the error. The jump goes elsewhere
    (often backward). Making it unconditional prevents the fall-through.

    Also detects already-patched sites (unconditional jmp or nop+jmp).
    """
    anchors = find_a005_locations(data)
    sites = []

    for anchor in anchors:
        candidates = []
        already_patched = []

        for dist in range(2, MAX_SCAN_DISTANCE + 1):
            pos = anchor - dist
            if pos < 0:
                break

            # Check for already-patched short jmp (0xEB rel8)
            if data[pos] == 0xEB:
                disp = data[pos + 1]
                if disp > 127:
                    disp -= 256
                target = pos + 2 + disp
                if target > anchor + MOV_EAX_A005_LEN:
                    already_patched.append({
                        "anchor": anchor,
                        "patch_offset": pos,
                        "opcode": 0xEB,
                        "jump_type": "short",
                        "target": target,
                        "distance": dist,
                        "patched": True,
                    })
                elif _is_fall_through_guard(data, pos, 2, anchor, target):
                    already_patched.append({
                        "anchor": anchor,
                        "patch_offset": pos,
                        "opcode": 0xEB,
                        "jump_type": "short",
                        "target": target,
                        "distance": dist,
                        "patched": True,
                    })

            # Check for already-patched near jmp (90 E9 rel32)
            if pos >= 1 and data[pos - 1] == 0x90 and data[pos] == 0xE9:
                if pos + 4 < len(data):
                    disp = struct.unpack_from("<i", data, pos + 1)[0]
                    target = pos + 5 + disp
                    if target > anchor + MOV_EAX_A005_LEN:
                        already_patched.append({
                            "anchor": anchor,
                            "patch_offset": pos - 1,
                            "opcode": 0xE9,
                            "jump_type": "near",
                            "target": target,
                            "distance": dist + 1,
                            "patched": True,
                        })

            # Check for short conditional jump (2 bytes: opcode + rel8)
            result = decode_short_jcc(data, pos)
            if result:
                condition, target = result
                # Pattern A: target skips past error
                if target > anchor + MOV_EAX_A005_LEN:
                    candidates.append({
                        "anchor": anchor,
                        "patch_offset": pos,
                        "opcode": condition,
                        "jump_type": "short",
                        "target": target,
                        "distance": dist,
                    })
                # Pattern B: fall-through is the error
                elif _is_fall_through_guard(data, pos, 2, anchor, target):
                    candidates.append({
                        "anchor": anchor,
                        "patch_offset": pos,
                        "opcode": condition,
                        "jump_type": "short",
                        "target": target,
                        "distance": dist,
                    })

            # Check for near conditional jump (6 bytes: 0F opcode + rel32)
            if pos >= 1:
                result = decode_near_jcc(data, pos - 1)
                if result:
                    condition, target = result
                    near_pos = pos - 1
                    # Pattern A: target skips past error
                    if target > anchor + MOV_EAX_A005_LEN:
                        candidates.append({
                            "anchor": anchor,
                            "patch_offset": near_pos,
                            "opcode": condition,
                            "jump_type": "near",
                            "target": target,
                            "distance": dist + 1,
                        })
                    # Pattern B: fall-through is the error
                    elif _is_fall_through_guard(
                        data, near_pos, 6, anchor, target
                    ):
                        candidates.append({
                            "anchor": anchor,
                            "patch_offset": near_pos,
                            "opcode": condition,
                            "jump_type": "near",
                            "target": target,
                            "distance": dist + 1,
                        })

        if already_patched:
            # Prefer the already-patched site closest to the anchor
            site = min(already_patched, key=lambda c: c["distance"])
            sites.append(site)
        elif candidates:
            sites.append(_select_best_candidate(candidates))

    return sites


def format_site(site):
    """Format a discovered patch site for display."""
    if site.get("patched"):
        name = "jmp (patched)"
    else:
        name = JCC_NAMES.get(site["opcode"], f"j?? (0x{site['opcode']:02X})")
    jtype = site["jump_type"]
    return (
        f"  0x{site['patch_offset']:06X}: {name} ({jtype}) "
        f"-> 0x{site['target']:06X}  "
        f"[guards mov eax, 0xa005 at 0x{site['anchor']:06X}, "
        f"dist={site['distance']}]"
    )


def apply_discovered_patches(filepath, data, sites):
    """Apply patches from auto-discovered sites."""
    backup = filepath + ".orig"
    if not os.path.exists(backup):
        shutil.copy2(filepath, backup)
        print(f"Backup saved to {backup}")

    with open(filepath, "r+b") as f:
        for site in sites:
            offset = site["patch_offset"]
            opcode = site["opcode"]
            name = JCC_NAMES.get(opcode, f"0x{opcode:02X}")

            if site.get("patched"):
                print(f"  [SKIP] 0x{offset:06X}: already patched")
                continue

            if site["jump_type"] == "short":
                f.seek(offset)
                current = f.read(1)[0]
                if current == 0xEB:
                    print(f"  [SKIP] 0x{offset:06X}: already patched")
                    continue
                if current != opcode:
                    print(
                        f"  [WARN] 0x{offset:06X}: expected {name} "
                        f"(0x{opcode:02X}), found 0x{current:02X}"
                    )
                    continue
                f.seek(offset)
                f.write(b"\xEB")
                print(f"  [OK]   0x{offset:06X}: {name} -> jmp (short)")
            else:
                # Near conditional jump: 0F 8x rel32 -> 90 E9 rel32
                f.seek(offset)
                current = f.read(2)
                expected = bytes([NEAR_JCC_PREFIX, opcode + 0x10])
                if current == b"\x90\xE9":
                    print(f"  [SKIP] 0x{offset:06X}: already patched")
                    continue
                if current != expected:
                    print(
                        f"  [WARN] 0x{offset:06X}: expected "
                        f"{expected.hex()}, found {current.hex()}"
                    )
                    continue
                f.seek(offset)
                f.write(b"\x90\xE9")
                print(f"  [OK]   0x{offset:06X}: {name} -> nop+jmp (near)")

    print("Done.")


def show_find_offsets(data):
    """Display detailed offset discovery information."""
    print("\nSearching for 'mov eax, 0xa005' (signature check failure points)...")
    locations = find_a005_locations(data)
    if not locations:
        print("No instances found - this binary may not have signature checks.")
        return

    print(f"Found {len(locations)} instance(s):\n")
    for loc in locations:
        context_start = max(0, loc - 16)
        context = data[context_start : loc + 8]
        hexdump = " ".join(f"{b:02X}" for b in context)
        print(f"  File offset 0x{loc:06X}")
        print(f"    Context: ...{hexdump}...")

        # Show all conditional jumps scanning backward
        for dist in range(2, MAX_SCAN_DISTANCE + 1):
            pos = loc - dist
            if pos < 0:
                break

            result = decode_short_jcc(data, pos)
            if result:
                condition, target = result
                name = JCC_NAMES.get(condition, f"0x{condition:02X}")
                skips = target > loc + MOV_EAX_A005_LEN
                fallthru = _is_fall_through_guard(
                    data, pos, 2, loc, target
                )
                if skips:
                    action = "SKIPS error <-- PATCH"
                elif fallthru:
                    action = "FALL-THROUGH guard <-- PATCH"
                else:
                    action = "does not skip error"
                print(
                    f"    dist={dist:2d}: 0x{pos:06X} {name} (short) "
                    f"-> 0x{target:06X} {action}"
                )

            if pos >= 1:
                result = decode_near_jcc(data, pos - 1)
                if result:
                    condition, target = result
                    near_pos = pos - 1
                    name = JCC_NAMES.get(condition, f"0x{condition:02X}")
                    skips = target > loc + MOV_EAX_A005_LEN
                    fallthru = _is_fall_through_guard(
                        data, near_pos, 6, loc, target
                    )
                    if skips:
                        action = "SKIPS error <-- PATCH"
                    elif fallthru:
                        action = "FALL-THROUGH guard <-- PATCH"
                    else:
                        action = "does not skip error"
                    print(
                        f"    dist={dist + 1:2d}: 0x{near_pos:06X} {name} (near) "
                        f"-> 0x{target:06X} {action}"
                    )
        print()

    sites = discover_patch_sites(data)
    if sites:
        print(f"Auto-discovery selected {len(sites)} patch site(s):")
        for site in sites:
            print(format_site(site))


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <mpengine.dll> [--find-offsets]")
        sys.exit(1)

    filepath = sys.argv[1]
    find_only = "--find-offsets" in sys.argv

    with open(filepath, "rb") as f:
        data = f.read()

    print(f"File: {filepath} ({len(data)} bytes)")

    if find_only:
        show_find_offsets(data)
        sys.exit(0)

    # Auto-discover patch sites
    anchors = find_a005_locations(data)
    print(f"\nFound {len(anchors)} 'mov eax, 0xa005' anchor(s).")
    print("Discovering VDM signature bypass patch sites...")
    sites = discover_patch_sites(data)

    if not sites:
        print("ERROR: No patch sites found.")
        print("This binary may not have VDM signature checks,")
        print("or uses a pattern this tool doesn't recognize.")
        print("Run with --find-offsets for manual analysis.")
        sys.exit(1)

    print(f"Found {len(sites)} patch site(s):")
    for site in sites:
        print(format_site(site))

    unpatched_anchors = len(anchors) - len(sites)
    if unpatched_anchors > 0:
        print(
            f"\n  WARNING: {unpatched_anchors} anchor(s) had no "
            f"discoverable guard jump within {MAX_SCAN_DISTANCE} bytes."
        )
        print(
            "  These may use a code pattern this tool doesn't recognize."
        )
        print("  Run with --find-offsets to inspect manually.")

    print(f"\nApplying patches...")
    apply_discovered_patches(filepath, data, sites)


if __name__ == "__main__":
    main()
