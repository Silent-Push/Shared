# SpecterRAT String Decoder

# (C) SilentPush

def decode_bytes(input_bytes):
    xor_value = 0x48
    decoded = bytes(b ^ xor_value for b in input_bytes)

    print(decoded)

def get_operand(disasm_line):
    operand = disasm_line.split(",")[1].replace("h", "")[1:]
    
    if len(operand) % 2:
        operand = f"0{operand}"

    byte_array = bytes.fromhex(operand)

    # Reverse the byte order and return
    return byte_array[::-1]

def main():
    """
    Main routine to iterate over cross-references and decode strings.
    """

    # Iterate through all cross-references to the screen EA
    for xref in XrefsTo(get_screen_ea(), 0):
        if xref.type == 17:  # Type CALL
            # fun_start: start address of the function
            # fun_end: address of the cross-reference (end marker)
            fun_start = get_func_attr(xref.frm, FUNCATTR_START)
            fun_end = xref.frm
            final_bytes = b""

            # Loop through disassembled instructions in the function
            while True:
                disasm_line = GetDisasm(fun_start)

                # Look for operands in the instruction containing "[rbp+" or "[rsp+"
                if "[rbp+" in disasm_line and disasm_line.endswith("h"):
                    final_bytes += get_operand(disasm_line)

                if "[rsp+" in disasm_line and disasm_line.endswith("h"):
                    final_bytes += get_operand(disasm_line)

                fun_start = next_head(fun_start)

                if fun_start == fun_end:
                    decode_bytes(final_bytes)
                    break

if __name__ == "__main__":
    main()
