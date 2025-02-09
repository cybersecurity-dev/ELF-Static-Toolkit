#nm -C -D <file> | grep -w U | awk '{print $2}'
def extract_elf_import_info(elf_file, fpath):
    imported_funcs = {}
    
    for entry in elf_file.imported_symbols:
        if entry.name:
            version = entry.symbol_version.name if entry.has_version else "UNKNOWN"
            imported_funcs[f"{version}_{entry.name}"] = 1    
    
    return imported_funcs