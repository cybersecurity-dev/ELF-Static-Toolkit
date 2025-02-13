
# Extract ELF dynamic entries and symbols (equivalent to imports/exports)
# Symbol table '.dynsym' contains
def extract_elf_dynamic_info(elf_file) -> dict:
   # Extract dynamic symbols (used for runtime imports)
    dynamic_symbols = {}
    for symbol in elf_file.dynamic_symbols:
        dynamic_symbols[f"{symbol.name}_Value"] = hex(symbol.value)
        dynamic_symbols[f"{symbol.name}_Size"] = symbol.size
        dynamic_symbols[f"{symbol.name}_Type"] = symbol.type.name if symbol.type else "UNKNOWN",
        #dynamic_symbols[f"{symbol.name}_Version"] = symbol.symbol_version.name if symbol.has_version else "UNKNOWN"
        dynamic_symbols[f"{symbol.name}_Binding"] = symbol.binding.name if symbol.binding else "UNKNOWN",
        dynamic_symbols[f"{symbol.name}_Visibility"] = symbol.visibility.name if symbol.visibility else "UNKNOWN",
        dynamic_symbols[f"{symbol.name}_Ndx"] = str(symbol.shndx)  # Section index (Ndx) field
    return dynamic_symbols

#Extract ELF header information 
#Checked: readelf -d sample.elf
def extract_elf_shared_lib_info(elf_file) -> dict:
    shared_libraries = {}
    eentry = elf_file.dynamic_entries
    for entry in eentry:
        if entry.tag.name == "NEEDED":
            shared_libraries[f"{entry.name}_Tag"] = 1
            shared_libraries[f"{entry.name}_Tag_Type"] = entry.tag.name
        elif entry.tag.name == "NULL":
            shared_libraries[f"{hex(entry.value)}_Tag"] = 1 
            shared_libraries[f"{hex(entry.value)}_Tag_Type"] = entry.tag.name 
        else:
            shared_libraries[f"{hex(entry.value)}_Tag"] = 1  
            shared_libraries[f"{hex(entry.value)}_Tag_Type"] = entry.tag.name
    return shared_libraries