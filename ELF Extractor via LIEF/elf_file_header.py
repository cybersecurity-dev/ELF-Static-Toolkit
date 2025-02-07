
# Extract ELF header information 
# Checked: readelf  --file-header sample.elf
def extract_elf_file_header_info(elf_file) -> dict:
    eheader = elf_file.header
    header_info = {
        #"Magic": str(hex(eheader.identity)),
        "Magic": ' '.join(f'{byte:02x}' for byte in eheader.identity),
        "Class": str(eheader.identity_class.name),
        "Data": str(eheader.identity_data.name),
        "ELF Version": eheader.identity_version.name, # The ELF specification version (current version is 1).
        "OS/ABI": eheader.identity_os_abi.name,
        "ABI Version": eheader.identity_abi_version,
        "Type": str(eheader.file_type.name),
        "Machine": str(eheader.machine_type.name),
        "Version": eheader.object_file_version.name, #readelf 0x1 but mine is CURRENT, Check!
        "Entry point address": hex(eheader.entrypoint),
        "Start of program headers": eheader.program_header_offset,
        "Start of section headers": eheader.section_header_offset,    
        "Flags": hex(eheader.processor_flag),
        "Size of this header": eheader.header_size,
        "Size of program headers": eheader.program_header_size,        
        "Number of program headers": eheader.numberof_segments,        
        "Size of section headers": eheader.section_header_size,
        "Number of section headers": eheader.numberof_sections,
        "Section header string table index": eheader.section_name_table_idx        
    }
    return header_info