
# Extract ELF dynamic entries and symbols (equivalent to imports/exports)
# Symbol table '.dynsym' contains
def extract_elf_dynsym_symbol_table(elf_file, fpath) -> dict:
   # Extract dynamic symbols (used for runtime imports)
    dynamic_symbols = {}
    for symbol in elf_file.dynamic_symbols:
        dynamic_symbols[f"{symbol.name}_Value"] = hex(symbol.value)
        dynamic_symbols[f"{symbol.name}_Size"] = symbol.size
        
        try:
            dynamic_symbols[f"{symbol.name}_Type"] = symbol.type.name if symbol.type else "UNKNOWN"
        except ValueError as e: #ValueError: 15 is not a valid TYPE
            print(f"symbol type error:{fpath}")
            symbol_type_value = int(str(e).split()[0])
            dynamic_symbols[f"{symbol.name}_Type"] = f"symbol_type_value"
        
        #dynamic_symbols[f"{symbol.name}_Version"] = symbol.symbol_version.name if symbol.has_version else "UNKNOWN"
        
        try:
            dynamic_symbols[f"{symbol.name}_Binding"] = symbol.binding.name if symbol.binding else "UNKNOWN"
        except ValueError as e: #ValueError: 7 is not a valid BINDING.
            print(f"symbol binding error:{fpath}")
            binding_type_value = int(str(e).split()[0])
            dynamic_symbols[f"{symbol.name}_Binding"] = f"{binding_type_value}"
        
        try:    
            dynamic_symbols[f"{symbol.name}_Visibility"] = symbol.visibility.name if symbol.visibility else "UNKNOWN"
        except ValueError as e: #ValueError: 95 is not a valid VISIBILITY
            print(f"symbol visibility error:{fpath}")
            visibility_value = int(str(e).split()[0])
            dynamic_symbols[f"{symbol.name}_Visibility"] = f"{visibility_value}"
        dynamic_symbols[f"{symbol.name}_Ndx"] = str(symbol.shndx)  # Section index (Ndx) field
    return dynamic_symbols

#Extract ELF dynamic section (if present)
#Checked: readelf --dynamic sample.elf
def extract_elf_dynamic_section_info(elf_file) -> dict:
    shared_libraries = {}
    eentry = elf_file.dynamic_entries
    for entry in eentry:
        try:
            tag_name = str(entry.tag)
        except:
            tag_name = f"UNKNOWN"  # Handle unknown tags

        if tag_name == "NEEDED":
            shared_libraries[f"{entry.name}_Tag"] = 1
            shared_libraries[f"{entry.name}_Tag_Type"] = tag_name
        elif tag_name == "NULL":
            shared_libraries[f"{hex(entry.value)}_Tag"] = 1 
            shared_libraries[f"{hex(entry.value)}_Tag_Type"] = tag_name
        else:
            shared_libraries[f"{hex(entry.value)}_Tag"] = 1  
            shared_libraries[f"{hex(entry.value)}_Tag_Type"] = tag_name
    return shared_libraries