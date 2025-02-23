
# Function to extract information from the version requirement section 
# Checked readelf --version-info  sample.elf
# .gnu.version_r
def extract_elf_file_version_needs(elf_file) -> dict:
    # Extract version needs section information
    version_needs_info = {}
    for version_need in elf_file.symbols_version_requirement:
        version_needs_info[f"{version_need.name}"] = 1       
        #Class which represents an entry defined in DT_VERDEF or .gnu.version_d
        for aux in version_need.get_auxiliary_symbols():
            version_needs_info[f"{version_need.name}_{aux.name}"] = 1
            version_needs_info[f"{version_need.name}_{aux.name}_flag"] = aux.flags
            version_needs_info[f"{version_need.name}_{aux.name}_version"] = aux.other
    return version_needs_info