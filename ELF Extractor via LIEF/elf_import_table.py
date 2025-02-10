import lief

#nm -C -D <file> | grep -w U | awk '{print $2}'
def extract_elf_import_info(elf_file, fpath):
    imported_funcs = {}
    
    for entry in elf_file.imported_symbols:
        if entry.name:
            version = "Unknown"
            if entry.has_version:
                symbol_version = entry.symbol_version
                if isinstance(symbol_version, lief.ELF.SymbolVersionAux):
                    version = symbol_version.name
                elif isinstance(symbol_version, lief.ELF.SymbolVersionAuxRequirement):
                    version = symbol_version.name
            imported_funcs[f"{version}_{entry.name}"] = 1
    return imported_funcs