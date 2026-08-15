#!/usr/bin/env python3
"""Convert a PPC2 TAS57xx .cfg file (I2C write commands) to a C header or raw
binary with a packed byte stream: each command is [reg, len, data[0..len-1]]
with no padding. The stream is terminated by 0xFF, 0xFF.

Usage:
  python3 convert_cfg.py tt_hf1.cfg           # C header to stdout
  python3 convert_cfg.py --bin tt_hf1.cfg      # raw .bin file
"""

import sys

# TAS575x/578x register names by page
# Page 0x00: Device Control
PAGE0_REGS = {
    0x00: "Page select",
    0x01: "Reset",
    0x02: "Standby/Shutdown ctrl",
    0x03: "Mute",
    0x04: "PLL/DSP source",
    0x05: "De-emphasis / SDOUT / Auto-detect",
    0x06: "SDOUT select",
    0x07: "GPIO/SDOUT",
    0x08: "GPIO enable",
    0x09: "BCK/LRCLK config",
    0x0C: "Master mode BCK divider",
    0x0D: "PLL reference clock",
    0x0E: "DAC reference clock",
    0x0F: "PLL divider P",
    0x10: "PLL multiplier J",
    0x11: "PLL divider D (MSB)",
    0x12: "PLL divider D (LSB)",
    0x13: "PLL divider R",
    0x14: "DSP clock divider",
    0x15: "DAC clock divider",
    0x16: "NCP clock divider",
    0x17: "OSR clock divider",
    0x1B: "Master BCK divider",
    0x1C: "Master LRCLK divider (MSB)",
    0x1D: "Master LRCLK divider (LSB)",
    0x20: "IDAC (MSB)",
    0x21: "IDAC (LSB)",
    0x22: "FS speed mode",
    0x25: "Ignore errors",
    0x28: "I2S config",
    0x2A: "DAC data path",
    0x2B: "DSP program select",
    0x3C: "Clock detect",
    0x3D: "Digital volume fine (Ch B)",
    0x3E: "Digital volume fine (Ch A)",
    0x3F: "Auto mute time",
    0x40: "Digital volume ctrl",
    0x41: "Volume ramp config",
    0x44: "Digital volume L",
    0x45: "Digital volume R",
    0x48: "Auto mute ctrl",
    0x54: "Mute output select",
    0x55: "GPIO output select",
    0x56: "Analog output enable",
    0x59: "GPIO output ctrl",
    0x5C: "FS speed detect",
    0x6A: "Output amplitude ctrl",
    0x6B: "Output amplitude ctrl 2",
    0x6C: "Undervoltage protection",
    0x6E: "Power stage ctrl 1",
    0x6F: "Power stage ctrl 2",
    0x70: "Power stage ctrl 3",
    0x71: "Power stage ctrl 4",
    0x76: "VCOM ramp rate",
    0x77: "VCOM power ctrl",
    0x78: "VCOM power ctrl 2",
}

# Page 0x01: Output Control
PAGE1_REGS = {
    0x00: "Page select",
    0x01: "Output amplitude ctrl",
    0x02: "Analog gain ctrl",
    0x06: "Analog output ctrl",
    0x07: "Analog boost ctrl",
    0x08: "Analog boost ctrl 2",
}

# DSP coefficient page descriptions
DSP_PAGE_NAMES = {
    # miniDSP A (Channel A) coefficient pages
    0x2C: "DSP-A: Process block coefficients",
    0x2D: "DSP-A: Process block coefficients (cont.)",
    0x2E: "DSP-A: Biquad filters",
    0x2F: "DSP-A: Biquad filters (cont.)",
    0x30: "DSP-A: Biquad/DRC",
    0x31: "DSP-A: DRC/filters",
    0x32: "DSP-A: Mixer/crossover",
    0x33: "DSP-A: Interpolation/misc",
    0x34: "DSP-A: Adaptation",
    # miniDSP B (Channel B) coefficient pages (mirror of A)
    0x3E: "DSP-B: Process block coefficients",
    0x3F: "DSP-B: Process block coefficients (cont.)",
    0x40: "DSP-B: Biquad filters",
    0x41: "DSP-B: Biquad filters (cont.)",
    0x42: "DSP-B: Biquad/DRC",
    0x43: "DSP-B: DRC/filters",
    0x44: "DSP-B: Mixer/crossover",
    0x45: "DSP-B: Interpolation/misc",
    0x46: "DSP-B: Adaptation",
}

# These pages contain miniDSP instruction RAM
INSTRUCTION_PAGES = set(range(0x98, 0xAA))


def get_reg_comment(page, reg, data_len):
    """Return a register annotation comment, or empty string."""
    if page == 0x00:
        name = PAGE0_REGS.get(reg)
        if name:
            return f"  // {name}"
        # Multi-byte writes might span known regs
        for offset in range(data_len):
            if (reg + offset) in PAGE0_REGS:
                names = []
                for o in range(data_len):
                    n = PAGE0_REGS.get(reg + o, f"0x{reg+o:02X}")
                    names.append(n)
                return f"  // {' / '.join(names)}"
    elif page == 0x01:
        name = PAGE1_REGS.get(reg)
        if name:
            return f"  // {name}"
    elif page == 0x7F:
        if reg == 0x00:
            return "  // Book select"
    return ""


def get_page_comment(page):
    """Return extra context for a page select comment."""
    if page in DSP_PAGE_NAMES:
        return f" — {DSP_PAGE_NAMES[page]}"
    if page in INSTRUCTION_PAGES:
        return " — miniDSP instruction RAM"
    if page == 0x00:
        return " — Device Control"
    if page == 0x01:
        return " — Output Control"
    return ""


def convert(cfg_path, dev='98'):
    with open(cfg_path) as f:
        lines = f.readlines()

    name = cfg_path.rsplit('/', 1)[-1].rsplit('.', 1)[0]

    out = []
    out.append(f"// Auto-generated from {cfg_path}")
    out.append(f"// Packed byte stream: each command is [reg, len, data...]")
    out.append(f"// Terminated by 0xFF, 0xFF")
    out.append("")
    out.append("#pragma once")
    out.append("")
    out.append("#include <stdint.h>")
    out.append("")
    out.append(f"static const uint8_t {name}_seq[] = {{")

    current_page = 0x00
    pending_comments = []
    total_bytes = 0

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith('#'):
            pending_comments.append(stripped)
            continue
        if stripped.startswith('w '):
            parts = stripped.split()
            if parts[1].lower() != dev:
                continue
            reg = int(parts[2], 16)
            data_bytes = parts[3:]
            data_len = len(data_bytes)

            data_hex = ', '.join(f'0x{b.upper()}' for b in data_bytes)

            # Track page changes
            is_page_select = (reg == 0x00 and data_len == 1)
            if is_page_select:
                new_page = int(data_bytes[0], 16)

            # Emit pending comments
            for c in pending_comments:
                comment_text = c.lstrip('# ').strip()
                if comment_text:
                    if comment_text.startswith("Setting Page"):
                        page_num = int(comment_text.split("0x")[1], 16)
                        extra = get_page_comment(page_num)
                        out.append(f'    // {comment_text}{extra}')
                    else:
                        out.append(f'    // {comment_text}')
            pending_comments = []

            # Build register annotation
            reg_comment = ""
            if is_page_select:
                current_page = new_page
                reg_comment = "  // Page select"
            elif reg == 0x7F:
                reg_comment = "  // Book select"
            else:
                reg_comment = get_reg_comment(current_page, reg, data_len)

            out.append(
                f'    0x{reg:02X}, {data_len}, {data_hex},{reg_comment}'
            )
            total_bytes += 2 + data_len  # reg + len + data

    out.append('    0xFF, 0xFF  // end of stream')
    total_bytes += 2
    out.append('};')
    out.append(f'// Total: {total_bytes} bytes')
    out.append('')

    return '\n'.join(out)


def convert_bin(cfg_path, dev='98'):
    """Convert a .cfg file to a raw binary packed byte stream."""
    with open(cfg_path) as f:
        lines = f.readlines()

    data = bytearray()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if stripped.startswith('w '):
            parts = stripped.split()
            if parts[1].lower() != dev:
                continue
            reg = int(parts[2], 16)
            data_bytes = [int(b, 16) for b in parts[3:]]
            data.append(reg)
            data.append(len(data_bytes))
            data.extend(data_bytes)

    data.extend([0xFF, 0xFF])
    return bytes(data)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} [--bin] [--addr XX] <cfg_file>",
              file=sys.stderr)
        sys.exit(1)

    args = sys.argv[1:]
    bin_mode = '--bin' in args
    dev = '98'
    if '--addr' in args:
        i = args.index('--addr')
        dev = args[i + 1].lower()
        del args[i:i + 2]
    cfg_file = [a for a in args if a != '--bin'][0]

    if bin_mode:
        out_path = cfg_file.rsplit('.', 1)[0] + '.bin'
        data = convert_bin(cfg_file, dev)
        with open(out_path, 'wb') as f:
            f.write(data)
        print(f"Wrote {len(data)} bytes to {out_path}", file=sys.stderr)
    else:
        print(convert(cfg_file, dev))
