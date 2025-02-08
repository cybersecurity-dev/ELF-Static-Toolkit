import ssdeep

from elf_metadata import shannon_entropy

#Section Headers  
# Checked  readelf --section-headers sample.elf
def extract_elf_section_headers_info(elf_file, fpath) -> dict:
    # Extract section information
    esections = elf_file.sections
    sections_info = {
        "Number of Sections": len(elf_file.sections)
    }
    for section_idx, section in enumerate(esections):
        section_info_prefix = f"{section_idx}_{section.name if section.name else "NULL"}"

        sections_info[f"{section_info_prefix}_type"] = section.type.name if section.type.name != "SHT_NULL_" else "NULL"
        sections_info[f"{section_info_prefix}_virtual_address"] = hex(section.virtual_address)
        sections_info[f"{section_info_prefix}_offset"] = hex(section.offset),
        sections_info[f"{section_info_prefix}_size"] = hex(section.size),
        sections_info[f"{section_info_prefix}_entry_size"] = section.entry_size,
        sections_info[f"{section_info_prefix}_flags"] = str(section.flags),  # Flags as bit field
        sections_info[f"{section_info_prefix}_link"] = section.link,      
        sections_info[f"{section_info_prefix}_information"] = section.information,      
        sections_info[f"{section_info_prefix}_alignment"] = section.alignment,
        sections_info[f"{section_info_prefix}_entropy"] = section.entropy,
        
        section_content = bytes(section.content)  # Ensure content is bytes
        sections_info[f"{section_info_prefix}_content"] = ' '.join([f'{byte:02x}' for byte in section_content[:15]])
        
        sections_info[f"{section_info_prefix}_shannon_entropy"] = shannon_entropy(section_content)
        try:
            sections_info[f"{section_info_prefix}_ssdeep_hash"] = ssdeep.hash(section_content)
        except Exception as e:
            print(f"Error calculating ssdeep for section {section.type}: {e}")
            sections_info[f"{section_info_prefix}_ssdeep_hash"] = "Error" # Or some other indicator
    return sections_info