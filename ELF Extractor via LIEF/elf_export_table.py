#nm -C -D <file> | grep -w T | awk '{print $3}'
def extract_elf_export_info(elf_file, fpath):
    exported_funcs = {}
    
    for symbol in elf_file.exported_functions:
        if symbol.name:
            exported_funcs[f"{symbol.name}"] = 1    
   
    return exported_funcs