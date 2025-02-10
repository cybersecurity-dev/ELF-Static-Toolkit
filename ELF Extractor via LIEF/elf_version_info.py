
# Function to extract information from the version requirement section 
# ##Checked readelf --version-info  sample.elf
def extract_elf_file_version_needs(elf_file) -> dict:
    # Extract version needs section information
    version_needs_info = {}
    for version_need in elf_file.symbols_version_requirement:
        for aux_idx, aux in enumerate(version_need.get_auxiliary_symbols()):
            #print(aux)
            version_needs_info[f"{aux_idx}_version_{version_need.version}_needs_{version_need.name}_name"] = aux.name
            version_needs_info[f"{aux_idx}_version_{version_need.version}_needs_{version_need.name}_flag"] = aux.flags
            version_needs_info[f"{aux_idx}_version_{version_need.version}_needs_{version_need.name}_version"] = aux.other    
    return version_needs_info