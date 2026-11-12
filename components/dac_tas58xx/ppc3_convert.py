#!/usr/bin/env python3
"""Convert a tuned PPC3 TAS58xx configuration into the byte stream the
firmware replays at init.

PPC3 can export a tuning two ways and both are accepted here:

  * an I2C log (.cfg), lines of  ``w <dev> <reg> <data...>``  and  ``d <ms>``
  * a C header, a ``cfg_reg`` array of ``{reg, value}`` pairs using the
    ``CFG_META_DELAY`` / ``CFG_META_BURST`` markers

Output is a packed stream of ``[reg, len, data[0..len-1]]`` commands ending in
``0xFF 0xFF``, with ``[0xFE, 1, ms]`` for a pause. TAS58xx register addresses
are 7-bit, so neither marker can collide with a real write.

  python3 ppc3_convert.py tuning.cfg -o data/hf/tas5825m_fw.bin
  python3 ppc3_convert.py tuning.h   -o data/hf/tas5825m_fw0.bin
  python3 ppc3_convert.py tuning.cfg --dev 9a -o data/hf/tas5825m_fw1.bin
"""

import argparse
import re
import sys

OP_DELAY = 0xFE
OP_END = 0xFF

# A block write auto-increments the register address and stops at the end of
# the page, so a command may not straddle 0x7F.
PAGE_LIMIT = 0x80

CFG_META_SWITCH = 255
CFG_META_DELAY = 254
CFG_META_BURST = 253


def emit(out, reg, data):
    """Append one write. A block write auto-increments the register address, so
    it may not run past the end of the page — the next page is a different
    block, and silently continuing there would corrupt it."""
    if reg in (OP_DELAY, OP_END):
        raise ValueError(f"register 0x{reg:02X} collides with a stream marker")
    if not data:
        return
    if len(data) > 255 or reg + len(data) > PAGE_LIMIT:
        raise ValueError(f"write of {len(data)} bytes at reg 0x{reg:02X} "
                         f"runs past the end of the page")
    out.append(bytes([reg, len(data)]) + bytes(data))


def emit_delay(out, ms):
    out.append(bytes([OP_DELAY, 1, min(max(ms, 0), 255)]))


# The page and book selects decide which block the following writes land in,
# so a block write may neither absorb them nor run through them.
PAGE_REGS = (0x00, 0x7F)


def coalesce(cmds):
    """Merge adjacent writes into auto-increment block writes.

    An I2C log carries one single-byte write per line, costing three bytes and
    a separate transaction each. This matters most on a sample-rate change,
    where the dump is replayed to re-tune a device that is already streaming.
    """
    out = []
    for cmd in cmds:
        reg, data = cmd[0], cmd[2:]
        if out and reg not in PAGE_REGS and reg != OP_DELAY:
            prev, prev_data = out[-1][0], out[-1][2:]
            if (prev not in PAGE_REGS and prev != OP_DELAY
                    and prev + len(prev_data) == reg
                    and len(prev_data) + len(data) <= 255
                    and reg + len(data) <= PAGE_LIMIT):
                out[-1] = (bytes([prev, len(prev_data) + len(data)])
                           + prev_data + data)
                continue
        out.append(cmd)
    return out


def parse_cfg(lines, want_dev):
    """Parse a PPC3 I2C log."""
    out = []
    seen = set()
    for lineno, raw in enumerate(lines, 1):
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        op = parts[0].lower()

        if op == 'w':
            if len(parts) < 3:
                raise ValueError(f"line {lineno}: short write")
            dev = parts[1].lower()
            seen.add(dev)
            if want_dev and dev != want_dev:
                continue
            emit(out, int(parts[2], 16), [int(b, 16) for b in parts[3:]])
        elif op in ('d', 'delay'):
            emit_delay(out, int(parts[1], 0))
        elif op in ('r', '#'):
            continue  # reads are diagnostics, not configuration
        else:
            print(f"warning: line {lineno}: ignoring '{op}'", file=sys.stderr)

    if want_dev and want_dev not in seen:
        raise ValueError(
            f"no writes for device {want_dev}; log contains {sorted(seen)}")
    return out, seen


PAIR_RE = re.compile(r'\{\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)\s*\}')


def _value(tok):
    if tok == 'CFG_META_SWITCH':
        return CFG_META_SWITCH
    if tok == 'CFG_META_DELAY':
        return CFG_META_DELAY
    if tok == 'CFG_META_BURST':
        return CFG_META_BURST
    return int(tok, 0)


def parse_header(text):
    """Parse a PPC3 cfg_reg array."""
    pairs = [(_value(a), _value(b)) for a, b in PAIR_RE.findall(text)]
    if not pairs:
        raise ValueError("no {reg, value} pairs found")

    out = []
    i = 0
    while i < len(pairs):
        reg, val = pairs[i]
        if reg == CFG_META_DELAY:
            emit_delay(out, val)
            i += 1
        elif reg == CFG_META_BURST:
            # val counts the register address plus its data, packed across the
            # following pairs as a flat byte stream.
            need = (val // 2) + 1
            flat = []
            for a, b in pairs[i + 1:i + 1 + need]:
                flat += [a, b]
            if len(flat) < val:
                raise ValueError("burst runs past the end of the array")
            emit(out, flat[0], flat[1:val])
            i += 1 + need
        elif reg == CFG_META_SWITCH:
            i += 1  # bank switch marker, nothing to send
        else:
            emit(out, reg, [val])
            i += 1
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('source', help='PPC3 .cfg log or exported .h header')
    ap.add_argument('-o', '--output', help='output .bin (default: stdout as C)')
    ap.add_argument('--dev', help='I2C write address to keep, e.g. 98 or 9a '
                                  '(.cfg only; required if the log has several)')
    args = ap.parse_args()

    with open(args.source, 'r', encoding='utf-8', errors='replace') as f:
        text = f.read()

    if ('CFG_META' in text and '{' in text) or args.source.endswith('.h'):
        cmds = parse_header(text)
        seen = set()
    else:
        want = re.sub(r'^0x', '', args.dev.lower()) if args.dev else None
        cmds, seen = parse_cfg(text.splitlines(), want)
        if want is None and len(seen) > 1:
            raise SystemExit(
                f"log targets {sorted(seen)}; pick one with --dev")

    raw = len(cmds)
    cmds = coalesce(cmds)
    stream = b''.join(cmds) + bytes([OP_END, OP_END])

    if args.output:
        with open(args.output, 'wb') as f:
            f.write(stream)
        print(f"{args.output}: {raw} writes merged into {len(cmds)} "
              f"commands, {len(stream)} bytes", file=sys.stderr)
    else:
        print(f"/* Generated from {args.source} */")
        print("static const uint8_t tas5825m_fw[] = {")
        for i in range(0, len(stream), 12):
            row = ', '.join(f'0x{b:02X}' for b in stream[i:i + 12])
            print(f"    {row},")
        print("};")


if __name__ == '__main__':
    main()
