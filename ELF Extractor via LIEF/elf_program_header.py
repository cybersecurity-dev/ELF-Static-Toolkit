import lief
import ssdeep

from elf_metadata import shannon_entropy

def get_number_of_segment(fpath):
    try:
        binary = lief.parse(fpath)
    except Exception as e:
        raise Exception(f"Failed to parse the binary: {str(e)}")
    return len(binary.segments)

def get_segment_flags(flags):
    readable = False
    writable = False
    executable = False

    if isinstance(flags, str):  # LIEF sometimes returns strings
        readable = "R" in flags 
        writable = "W" in flags
        executable = "X" in flags
    elif isinstance(flags, int):  # Sometimes it returns integers (raw flags)
        readable = bool(flags & lief.ELF.PF_R)
        writable = bool(flags & lief.ELF.PF_W)
        executable = bool(flags & lief.ELF.PF_X)
    else:
        print(f"Unknown flags type: {type(flags)}")
        return None , None, None # Or raise an exception

    return readable, writable, executable
def convert_segment_flags_to_str(seg_flag) -> str:
        flags = []
        # Define constants for segment flags
        PF_R = 0x4  # Readable
        PF_W = 0x2  # Writable
        PF_X = 0x1  # Executable

        if int(seg_flag) & PF_R:
            flags.append("R")
        if int(seg_flag) & PF_W:
            flags.append("W")
        if int(seg_flag) & PF_X:
            flags.append("E")
        return "".join(flags)

def classify_segment_type(type_value: int) -> str:
    """Classify ELF segment type into categories."""
    # Standard ELF types (0x0-0x7)
    if type_value <= 0x7:
        return "Standard ELF"
    
    # OS-specific range (PT_LOOS to PT_HIOS)
    if 0x60000000 <= type_value <= 0x6FFFFFFF:
        return "OS-specific"
    
    # Processor-specific range (PT_LOPROC to PT_HIPROC)
    if 0x70000000 <= type_value <= 0x7FFFFFFF:
        return "Processor-specific"
    
    # GNU extensions
    gnu_types = {
        0x6474e550: "GNU Extension (EH_FRAME)",
        0x6474e551: "GNU Extension (STACK)",
        0x6474e552: "GNU Extension (RELRO)",
        0x6474e553: "GNU Extension (PROPERTY)"
    }
    if type_value in gnu_types:
        return gnu_types[type_value]
    
    return "UNKNOWN"

def get_program_header_type_category(segment, fpath):
    try:
        Program_Headers_Type_Name = ""
        Program_Headers_Category = ""
        seg_type_value = segment.type.value
        Program_Headers_Category = classify_segment_type(seg_type_value)
        if Program_Headers_Category in ("UNKNOWN"):
            Program_Headers_Type_Name = f"UNKNOWN (0x{seg_type_value:x})"
            return Program_Headers_Type_Name, f"SPECIFIC"
        #print(f"============>{segment.type.name}==={fpath}")

        return segment.type.name, Program_Headers_Category
    except:
        print(f"Exception at get_program_header_type_category:{fpath}")
        return f"UNKNOWN", f"SPECIFIC"

#Program Headers/Segment 
##Checked  readelf --program-headers sample.elf
def extract_elf_program_headers_info(elf_segments, fpath) -> dict:
    number_of_segment = get_number_of_segment(fpath)
    if not number_of_segment:
        return {}
    segments_info = {
        "Number of Segments": number_of_segment
    }

    for segment_idx, segment in enumerate(elf_segments):
        Program_Headers_Type, Program_Headers_Category = get_program_header_type_category(segment, fpath)
        if Program_Headers_Type == "PT_NULL_":
            continue
        segments_info[f"program_header_{segment_idx}_type"] = Program_Headers_Type
        segments_info[f"program_header_{segment_idx}_category"] = Program_Headers_Category
        segments_info[f"program_header_{segment_idx}_offset"] = hex(segment.file_offset)
        segments_info[f"program_header_{segment_idx}_virtual_address"] = hex(segment.virtual_address)
        segments_info[f"program_header_{segment_idx}_physical_address"] = hex(segment.physical_address)
        segments_info[f"program_header_{segment_idx}_file_size"] = hex(segment.physical_size)
        segments_info[f"program_header_{segment_idx}_memory_size"] = hex(segment.virtual_size)
        if Program_Headers_Type == "UNKNOWN":
            print(f"UNKNOWN program header type:{fpath}")
            segments_info[f"program_header_{segment_idx}_flags"] = ""
            segments_info[f"program_header_{segment_idx}_flags_READ"] = None
            segments_info[f"program_header_{segment_idx}_flags_WRITE"] = None
            segments_info[f"program_header_{segment_idx}_flags_EXECUTE"] = None
        else:
            segments_info[f"program_header_{segment_idx}_flags"] = convert_segment_flags_to_str(segment.flags)
            is_read, is_write, is_exec = get_segment_flags(segment.flags.name)
            segments_info[f"program_header_{segment_idx}_flags_READ"] = is_read
            segments_info[f"program_header_{segment_idx}_flags_WRITE"] = is_write
            segments_info[f"program_header_{segment_idx}_flags_EXECUTE"] = is_exec

        segments_info[f"program_header_{segment_idx}_segment_alignment"] = hex(segment.alignment)
        if Program_Headers_Type != "PT_NULL_":
            segment_content = bytes(segment.content)
            segments_info[f"program_header_{segment_idx}_segment_content"] = ' '.join([f'{byte:02x}' for byte in segment_content[:15]])
            segments_info[f"program_header_{segment_idx}_segment_shannon_entropy"] = shannon_entropy(segment_content)            
            try:
                segments_info[f"program_header_{segment_idx}_segment_ssdeep_hash"] = ssdeep.hash(segment_content)
            except Exception as e:
                print(f"Error calculating ssdeep for segment {Program_Headers_Type}: {e}")
                print(f"SSDEEP error:{fpath}")
                segments_info[f"program_header_{segment_idx}_segment_ssdeep_hash"] = "NONE" # Or some other indicator
        else:  
            #PT_NULL: This is a special type of segment in an executable file that doesn't contain any data. 
            #It's often used for padding or alignment purposes
            segments_info[f"program_header_{segment_idx}_segment_content"] = f"NONE"
            segments_info[f"program_header_{segment_idx}_segment_shannon_entropy"] = f"NONE"
            segments_info[f"program_header_{segment_idx}_segment_ssdeep_hash"] = f"NONE"

    return segments_info

# Extract segment-to-section mapping 
# Checked  readelf --program-headers sample.elf
def extract_segment_to_section_mapping(elf_segments, elf_sections, fpath) -> dict:
    segment_to_section_mapping_data = {}
    dictionary_key_prefix = f"section_to_segment_mapping_segment"
    
    for segment_idx, segment in enumerate(elf_segments):
        segment_to_section_mapping_data[f"{dictionary_key_prefix}{segment_idx}"] = 0
        controller = True
        for section in elf_sections:
            if  segment.virtual_address <= section.virtual_address < segment.virtual_address + segment.virtual_size:
                if section.name != "":
                    if controller:
                        value = segment_to_section_mapping_data.pop(f"{dictionary_key_prefix}{segment_idx}")
                        if value == "":
                            print(f"Error:{fpath}")
                        controller = not controller
                    segment_to_section_mapping_data[f"{dictionary_key_prefix}{segment_idx}_{section.name}"] = 1
                else:
                    segment_to_section_mapping_data[f"{dictionary_key_prefix}{segment_idx}"] = 0
    return segment_to_section_mapping_data