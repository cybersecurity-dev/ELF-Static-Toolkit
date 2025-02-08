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
        return segment.type.name, Program_Headers_Category
    except:
        print(f"Exception at get_program_header_type_category:{fpath}")
        return f"UNKNOWN", f"SPECIFIC"

#Program Headers/Segment 
##Checked  readelf --program-headers sample.elf
def extract_elf_program_headers_info(elf_file, fpath) -> dict:
    esegments = elf_file.segments
    number_of_segment = get_number_of_segment(fpath)
    if not number_of_segment:
        return {}
    segments_info = {
        "Number of Segments": number_of_segment
    }

    for segment_idx, segment in enumerate(esegments):
        Program_Headers_Type, Program_Headers_Category = get_program_header_type_category(segment, fpath)
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
        segment_content = bytes(segment.content)
        segments_info[f"program_header_{segment_idx}_segment_content"] = ' '.join([f'{byte:02x}' for byte in segment_content[:15]])
        segments_info[f"program_header_{segment_idx}_segment_shannon_entropy"] = shannon_entropy(segment_content)
        try:
            segments_info[f"program_header_{segment_idx}_segment_ssdeep_hash"] = ssdeep.hash(segment_content)
        except Exception as e:
            print(f"Error calculating ssdeep for segment {Program_Headers_Type}: {e}")
            print(f"SSDEEP error:{fpath}")
            segments_info[f"program_header_{segment_idx}_segment_ssdeep_hash"] = "Error" # Or some other indicator
    return segments_info