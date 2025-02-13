# Extract ELF header information 
# Checked: readelf  --file-header sample.elf
def extract_elf_file_header_info(elf_header, fpath) -> dict:
    header_info = {
        #"Magic": str(hex(elf_header.identity)),
        "Magic": ' '.join(f'{byte:02x}' for byte in elf_header.identity),
        "Class": str(elf_header.identity_class.name),
        "Data": str(elf_header.identity_data.name),
        "ELF Version": elf_header.identity_version.name, # The ELF specification version (current version is 1).
        "OS/ABI": elf_header.identity_os_abi.name,
        "ABI Version": elf_header.identity_abi_version,
        "Type": str(elf_header.file_type.name),
        "Machine": str(elf_header.machine_type.name),
        "Version": elf_header.object_file_version.name, #readelf 0x1 but mine is CURRENT, Check!
        "Entry point address": hex(elf_header.entrypoint),
        "Start of program headers": elf_header.program_header_offset,
        "Start of section headers": elf_header.section_header_offset,    
        "Flags": hex(elf_header.processor_flag),
        "Size of this header": elf_header.header_size,
        "Size of program headers": elf_header.program_header_size,        
        "Number of program headers": elf_header.numberof_segments,        
        "Size of section headers": elf_header.section_header_size,
        "Number of section headers": elf_header.numberof_sections,
        "Section header string table index": elf_header.section_name_table_idx        
    }
    return header_info