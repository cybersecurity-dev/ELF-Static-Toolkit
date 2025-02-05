import sys
import os
import os.path, time
import lief
import pandas as pd
import hashlib
import datetime
import subprocess
import math
import ssdeep
import csv

initflag = True

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def is_elf_file(filepath) -> bool:
    """
    Checks ELF file by inspecting its magic bytes.
    """
    with open(filepath, 'rb') as f:
        magic_bytes = f.read(4)
        return magic_bytes == b'\x7fELF'
    
def clear_log_file(log_file_path) -> bool:
    try:
        with open(log_file_path, "w"):  # Open in write mode, which truncates the file
            pass  # No need to write anything
        print(f"Log file '{log_file_path}' cleared.")
        return True
    except Exception as e:
        print(f"Error clearing log file: {e}")
    return False

def eprint_with_timestamp(*args, **kwargs):
    LOG_FILE = os.path.basename(__file__).split('.')[0] + "_err.log"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Format positional arguments (*args)
    args_str = " ".join(map(str, args))  # Convert all args to strings and join them

    # Format keyword arguments (**kwargs)
    kwargs_str = " ".join([f"{key}={value}" for key, value in kwargs.items()])

    # Combine everything into a single string
    if kwargs_str: #Check if kwargs is not empty
        message = f"{timestamp}: {args_str} {kwargs_str}\n"
    else:
         message = f"{timestamp}: {args_str}\n"

    # Append to log file
    try:
        with open(LOG_FILE, "a") as f:
            f.write(message)
    except Exception as e:
        print(f"Error writing to log file: {e}", file=sys.stderr)

def eprint(*args, **kwargs):
    global initflag
    LOG_FILE = os.path.basename(__file__).split('.')[0] + "_err.log"
    if initflag : 
        clear_log_file(LOG_FILE)
        initflag = False
    
    # Append to log file
    try:
        with open(LOG_FILE, "a") as f:
            f.write(*args, **kwargs)
            f.write("\n")
    except Exception as e:
        print(f"Error writing to log file: {e}", file=sys.stderr)

def is_binary(fpath):
    return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

def get_number_of_sections(fpath):
    try:
        binary = lief.parse(fpath)
    except Exception as e:
        raise Exception(f"Failed to parse the binary: {str(e)}")
    return len(binary.sections)

def get_number_of_program_headers(fpath):
    try:
        binary = lief.parse(fpath)
    except Exception as e:
        raise Exception(f"Failed to parse the binary: {str(e)}")
    return len(binary.segments)

def detect_architecture(fpath):
    binary = lief.parse(fpath)
    if binary is None:
        print(f"File is not Binary:{fpath}\n")
        raise Exception("Failed to parse the binary.")

    machine_type = binary.header.machine_type
    
    if machine_type == lief.ELF.ARCH.ARM:
        return "ARM (32-bit)"
    elif machine_type == lief.ELF.ARCH.AARCH64:
        return "ARM64"
    elif machine_type == lief.ELF.ARCH.MIPS:
        return "MIPS"
    elif machine_type == lief.ELF.ARCH.I386:
        return "Intel 80386"
    elif machine_type == lief.ELF.ARCH.X86_64:
        return "Intel x86-64"
    elif machine_type == lief.ELF.ARCH.PPC64:
        return "PowerPC64"
    elif machine_type == lief.ELF.ARCH.RISCV:
        return "RISC-V"
    elif machine_type == lief.ELF.ARCH.IA_64:
        return "IA-64 (Itanium)"
    else:
        return f"Unknown ELF architecture ({machine_type})"

def has_unsupported_unwind_sections(fpath):
    """Check if an ELF binary contains unwind sections for Intel 80386 (x86) architecture."""
    try:
        binary = lief.parse(fpath)
    except Exception as e:
        raise ValueError(f"Failed to parse file: {str(e)}")

    if not isinstance(binary, lief.ELF.Binary):
        return False  # Not an ELF binary

    # Check for Intel 80386 architecture
    if binary.header.machine_type != lief.ELF.ARCH.i386:
        return False  # Not x86

    # List of unwind-related sections to check
    unwind_sections = {
        '.eh_frame',      # Exception handling frame section
        '.eh_frame_hdr',  # Exception handling frame header
        '.debug_frame'    # Debug frame section
    }

    # Check if any unwind sections exist
    found_sections = []
    for section in binary.sections:
        if section.name in unwind_sections:
            found_sections.append(section.name)
    
    return len(found_sections) > 0

def get_elf_file_type(fpath):
    """Gets the ELF file type of an ELF file."""
    binary = lief.parse(fpath)
    if binary is None:
        raise Exception(f"Failed to parse:{fpath}")
        return None
    return binary.header.file_type.name

def get_elf_type(fpath):
    try:
        # Use the 'file' command to get file type information
        output = subprocess.check_output(['file', fpath], universal_newlines=True, stderr=subprocess.STDOUT)

        if "ELF" not in output:
          return None

        if "executable" in output:
            return "ET_EXEC"
        elif "shared object" in output:
            return "ET_DYN"
        elif "relocatable" in output:
            return "ET_REL"
        elif "core dumped" in output:
            return "ET_CORE"
        else:
            return None # Likely an ELF file, but unknown type.
    except FileNotFoundError:
        return None
    except subprocess.CalledProcessError as e:
        print(f"Error executing 'file' command: {e.output}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

def get_segment_flags(flags):
    readable = False
    writable = False
    executable = False

    if isinstance(flags, str):  # LIEF sometimes returns strings
        readable = "R" in flags 
        writable = "W" in flags
        executable = "E" in flags
    elif isinstance(flags, int):  # Sometimes it returns integers (raw flags)
        readable = bool(flags & lief.ELF.PF_R)
        writable = bool(flags & lief.ELF.PF_W)
        executable = bool(flags & lief.ELF.PF_X)
    else:
        print(f"Unknown flags type: {type(flags)}")
        return None , None, None # Or raise an exception

    return readable, writable, executable

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    # Frequency distribution of byte values (0-255)
    freq = [0] * 256
    for byte in data:
        # Ensure `byte` is treated as an integer
        freq[byte] += 1
    # Calculate entropy
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / len(data)
            entropy -= p * math.log2(p)
    return entropy

# Function to extract information from the version requirement section ##Checked readelf --version-info  sample.elf
def extract_elf_file_version_needs(elf_file) -> dict:
    # Extract version needs section information
    version_needs_info = {}
    for version_need in elf_file.symbols_version_requirement:
        for aux_idx, aux in enumerate(version_need.get_auxiliary_symbols()):
            version_needs_info[f"{aux_idx}_version_{version_need.version}_needs_{version_need.name}_name"] = aux.name
            version_needs_info[f"{aux_idx}_version_{version_need.version}_needs_{version_need.name}_flag"] = aux.flags
            version_needs_info[f"{aux_idx}_version_{version_need.version}_needs_{version_need.name}_version"] = aux.other    
    #elf_data.update(version_needs_info)
    return version_needs_info

def get_abi_version(elf):
    """Extracts the Build ID from an ELF binary using LIEF."""
    for note in elf.notes:
        #if note.name == "GNU" and note.type == lief.ELF.NOTE_TYPES.ABI_TAG:
        if note.name == "GNU" and note.type == 1:
            abi_version = (note.description[4], note.description[8], note.description[12])
            note_owner = note.name
            note_abi_version = '.'.join(map(str, abi_version[:3]))
            return note_owner, note_abi_version
    return None, None

def get_build_id(elf):
    """Extracts the ABI tag from an ELF binary using LIEF."""
    for note in elf.notes:
        #if  note.name == "GNU" and note.type == lief.ELF.NOTE_TYPES.GNU_BUILD_ID:
        if  note.name == "GNU" and note.type == 3:
            note_build_id = ''.join(f"{byte:02x}" for byte in note.description) if note.description else "None"
            #note_build_id = note.description.hex()
            note_owner = note.name
            return note_owner, note_build_id
    return None, None

def extract_elf_file_notes_info(elf) -> dict:
    owner = None
    build_id = None
    abi_version = None
    try:
        owner, build_id = get_build_id(elf)
        owner, abi_version = get_abi_version(elf)
    except lief.exception as lief_error:
        eprint(f"LIEF Error: {lief_error}")
    except Exception as e:
        eprint(f"An unexpected error occurred: {e}")
    return {"owner" : owner, "build_id" : build_id, "abi_version" : abi_version}

# Extract ELF header information ##Checked: readelf  --file-header sample.elf
def extract_elf_file_header_info(elf_file) -> dict:
    # Extract ELF header information
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
    # Add header information to the ELF data dictionary
    #print(header_info)
    #elf_data.update(header_info)
    return header_info

#Section Headers  ##Checked  readelf --section-headers sample.elf
def extract_elf_section_headers_info(elf_file) -> dict:
    # Extract section information
    esections = elf_file.sections
    sections_info = {
        "Number of Sections": len(elf_file.sections)
    }
    for section in esections:
        #if section.type == "NULL":
        #    continue
        sections_info[f"{section.name}_type"] = section.type.name if section.type else "UNKNOWN"
        sections_info[f"{section.name}_virtual_address"] = hex(section.virtual_address)
        sections_info[f"{section.name}_offset"] = hex(section.offset),
        sections_info[f"{section.name}_size"] = hex(section.size),
        sections_info[f"{section.name}_entry_size"] = section.entry_size,
        sections_info[f"{section.name}_flags"] = str(section.flags),  # Flags as bit field
        sections_info[f"{section.name}_link"] = section.link,      
        sections_info[f"{section.name}_information"] = section.information,      
        sections_info[f"{section.name}_alignment"] = section.alignment,
        sections_info[f"{section.name}_entropy"] = section.entropy,
        #sections_info[f"{section.name}_content"] = list(section.content[:10])  # First 10 bytes of raw data
        section_content = bytes(section.content)  # Ensure content is bytes
        sections_info[f"{section.name}_content"] = ' '.join([f'{byte:02x}' for byte in section_content[:15]])
        sections_info[f"{section.name}_shannon_entropy"] = shannon_entropy(section_content)
        try:
            sections_info[f"{section.name}_ssdeep_hash"] = ssdeep.hash(section_content)
            #print(ssdeep.hash(section_content))
        except Exception as e:
            print(f"Error calculating ssdeep for section {section.type}: {e}")
            sections_info[f"{section.name}_ssdeep_hash"] = "Error" # Or some other indicator

    #for key, value in sections_info.items():
    #    print(key, value)
    # Add section information to the ELF data dictionary
    #print(sections_info)
    return sections_info

#Program Headers/Segment ##Checked  readelf --program-headers sample.elf
def extract_elf_program_headers_info(elf_file) -> dict:
    # Extract segments information
    esegments = elf_file.segments
    segments_info = {
        "Number of Segments": len(elf_file.segments)
    }
    for segment_idx, segment in enumerate(esegments):
         # Extract the segment content as bytes

        Program_Headers_Type = segment.type.name if segment.type else "UNKNOWN"
        segments_info[f"segment_{segment_idx}_{Program_Headers_Type}_segment_offset"] = hex(segment.file_offset)
        segments_info[f"segment_{segment_idx}_{Program_Headers_Type}_segment_virtual_address"] = hex(segment.virtual_address)
        segments_info[f"segment_{segment_idx}_{Program_Headers_Type}_segment_physical_address"] = hex(segment.physical_address)
        segments_info[f"segment_{segment_idx}_{Program_Headers_Type}_segment_file_size"] = hex(segment.physical_size)
        segments_info[f"segment_{segment_idx}_{Program_Headers_Type}_segment_memory_size"] = hex(segment.virtual_size)
        is_read, is_write, is_exec = get_segment_flags(segment.flags.name)
        segments_info[f"{Program_Headers_Type}_segment_flags_READ"] = is_read
        segments_info[f"{Program_Headers_Type}_segment_flags_WRITE"] = is_write
        segments_info[f"{Program_Headers_Type}_segment_flags_EXECUTE"] = is_exec
        #print(f"----->{get_segment_flags(segment.flags.name)}")
        
        
        flags = []
        # Define constants for segment flags
        PF_R = 0x4  # Readable
        PF_W = 0x2  # Writable
        PF_X = 0x1  # Executable

        if int(segment.flags) & PF_R:
            flags.append("R")
        if int(segment.flags) & PF_W:
            flags.append("W")
        if int(segment.flags) & PF_X:
            flags.append("E")
            segments_info[f"segment_{segment_idx}_{Program_Headers_Type}_segment_is_executable"] = True
        else:
            segments_info[f"segment_{segment_idx}_{Program_Headers_Type}_segment_is_executable"] = False
     
        flags_str = "".join(flags)
        segments_info[f"segment_{segment_idx}_{Program_Headers_Type}_segment_flags"] = flags_str



        segments_info[f"segment_{segment_idx}_{Program_Headers_Type}_segment_alignment"] = segment.alignment
        segment_content = bytes(segment.content)
        segments_info[f"segment_{segment_idx}_{Program_Headers_Type}_segment_content"] = ' '.join([f'{byte:02x}' for byte in segment_content[:15]])
        segments_info[f"segment_{segment_idx}_{Program_Headers_Type}_segment_shannon_entropy"] = shannon_entropy(segment_content)
        try:
            segments_info[f"segment_{segment_idx}_{Program_Headers_Type}_segment_ssdeep_hash"] = ssdeep.hash(segment_content)
            #print(ssdeep.hash(segment_content))
        except Exception as e:
            print(f"Error calculating ssdeep for segment {Program_Headers_Type}: {e}")
            segments_info[f"segment_{segment_idx}_{Program_Headers_Type}_segment_ssdeep_hash"] = "Error" # Or some other indicator
    #for key, value in segments_info.items():
    #    print(key, value)
    # Add section information to the ELF data dictionary
    #print(segments_info)
    return segments_info
 
# Extract segment-to-section mapping ##Checked  readelf --program-headers sample.elf
def extract_segment_to_section_mapping(elf_file) -> dict:
    esegments = elf_file.segments
    esections = elf_file.sections
    segment_to_section_mapping_data = {}
    for segment_idx, segment in enumerate(esegments):
        sections_in_segment = []
        for section in esections:
            # Check if the section falls within the segment's range
            if segment.file_offset <= section.offset < segment.file_offset + segment.physical_size:
                if section.name != "":
                    segment_to_section_mapping_data[f"section_to_segment_mapping_segment{segment_idx}_{section.name}_"] = 1
                    #sections_in_segment.append(section.name)   
    #for key, value in segment_to_section_mapping_data.items():
    #    print(key, value)
    # Add section information to the ELF data dictionary
    #print(segment_to_section_mapping_data)
    return segment_to_section_mapping_data

def extract_elf_import_info(elf_file) -> dict:
    # Extract import table information
    dynamic_entries = elf_file.dynamic_entries
    import_info = { }

    iimp = 0
    for entry in dynamic_entries:
        if entry.tag == 1:
            iimp += 1
            #import_info[f"{iimp}_import_name"] = entry.name
            import_info[f"{entry.name}"] = 1
    #for key, value in import_info.items():
    #    print(key, value)
    # Add section information to the ELF data dictionary
    #print(import_info)
    return import_info

def extract_elf_export_info(elf_file) -> dict:
    # Extract export table information
    exported_symbols = elf_file.exported_symbols
    export_info = { }

    iexp = 0
    for symbol in exported_symbols:
        iexp += 1
        #export_info[f"{iexp}_export_name"] = symbol.name
        export_info[f"{symbol.name}"] = 1
    
    #for key, value in export_info.items():
    #    print(key, value)
    # Add section information to the ELF data dictionary
    # elf_data.update(export_info)
    return export_info

def extract_elf_shared_lib_info(elf_file) -> dict:
    # Extract shared libraries from the dynamic section
    shared_libraries = {}
    eentry = elf_file.dynamic_entries
    for entry in eentry:
        #if entry.tag == lief.ELF.DYNAMIC_TAG.NEEDED:  # Only needed shared libraries    
        if entry.tag.name == "NEEDED":  # Tag 1 corresponds to NEEDED
            shared_libraries[f"{entry.name}_Tag"] = str(entry.tag.name),  # Dynamic tag type
            #shared_libraries[f"{entry.name}_Type"] = str(entry.tag.)
    #for key, value in shared_libraries.items():
    #    print(key, value)
    #print(shared_libraries)
    return shared_libraries

# Extract ELF dynamic entries and symbols (equivalent to imports/exports)
def extract_elf_dynamic_info(elf_file) -> dict:
   # Extract dynamic symbols (used for runtime imports)
    dynamic_symbols = {}
    for symbol in elf_file.dynamic_symbols:
        dynamic_symbols[f"{symbol.name}_Value"] = hex(symbol.value)
        dynamic_symbols[f"{symbol.name}_Size"] = symbol.size
        dynamic_symbols[f"{symbol.name}_Type"] = symbol.type.name if symbol.type else "UNKNOWN",
        dynamic_symbols[f"{symbol.name}_Binding"] = symbol.binding.name if symbol.binding else "UNKNOWN",
        dynamic_symbols[f"{symbol.name}_Visibility"] = symbol.visibility.name if symbol.visibility else "UNKNOWN",
        dynamic_symbols[f"{symbol.name}_Ndx"] = str(symbol.shndx)  # Section index (Ndx) field

    #for key, value in dynamic_symbols.items():
    #    print(key, value)
    #print(dynamic_symbols)
    return dynamic_symbols

def elf_extractor_runner(binary_dir, csv_output_dir, is_malware):
    # hash_list = []
    indx = 0
    df = pd.DataFrame()
    
    for r, d, f in os.walk(binary_dir):
        for filename in f:
            full_file_path = os.path.join(r, filename)

            if not is_elf_file(full_file_path):
                eprint(f"File path:{full_file_path}\tis not ELF")
                continue
            if detect_architecture(full_file_path) not in ("Intel 80386", "Intel x86-64"):
                print(f"ELF is not Intel Architecture:{full_file_path}")
                continue
            if has_unsupported_unwind_sections(full_file_path):
                print(f"{full_file_path} is an x86 ELF with potential unsupported unwind sections")
                continue
            else:
                df_header  = pd.DataFrame()
                df_section = pd.DataFrame()
                df_segment = pd.DataFrame()
                df_import  = pd.DataFrame()
                df_export  = pd.DataFrame()
                               
                print(f"----------------------------START:{indx}---------------------------------------")
                now = datetime.datetime.now()
                date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
                print(f"File operation started at:{date_time}")
                elf_type = get_elf_file_type(full_file_path)
                print(f"Full_file_path:{full_file_path}")
                print(f"ELF type:{elf_type}")
                print(f"----------------------------START:{indx}---------------------------------------")
                
                elf = lief.parse(full_file_path)
                if not isinstance(elf, lief.ELF.Binary):
                    print(f"Error.")
                sha256_id = calculate_sha256(full_file_path)
                elf_parse_result = {'sha256_hash': sha256_id, 'filename': filename}

                elf_parse_result.update(extract_elf_file_header_info(elf))
                if get_number_of_sections(full_file_path):
                    elf_parse_result.update(extract_elf_section_headers_info(elf))
                if get_number_of_program_headers(full_file_path):
                    elf_parse_result.update(extract_elf_program_headers_info(elf))
                elf_parse_result.update(extract_segment_to_section_mapping(elf))
                elf_parse_result.update(extract_elf_import_info(elf))
                elf_parse_result.update(extract_elf_export_info(elf))
                elf_parse_result.update(extract_elf_dynamic_info(elf))
                elf_parse_result.update(extract_elf_shared_lib_info(elf))
                elf_parse_result.update(extract_elf_file_version_needs(elf))
                elf_parse_result.update(extract_elf_file_notes_info(elf))
                
                binary_label = int(1) if is_malware else int(0)
                elf_parse_result.update({"ELF_TYPE": elf_type, "label" : binary_label})
                
                df_tmp = pd.DataFrame.from_dict(elf_parse_result)
                #df_tmp.insert(0, 'sha256_hash', sha256_id)
                #df.at[indx, 'label'] = int(1) if is_malware else int(0)

                print(f"----------------------------END:{indx}---------------------------------------")
                # Save DataFrame as CSV
                df_csv_path = f"{csv_output_dir}/{sha256_id}.csv"
                df_tmp.to_csv(df_csv_path, index=False, quoting=csv.QUOTE_NONNUMERIC)
                print(f"{filename} information saved into csv:\n{df_csv_path}")

                df_json_path = f"{csv_output_dir}/{sha256_id}.json"
                df_tmp.to_json(df_json_path, orient='records', indent=4)
                print(f"{filename} information saved into JSON:\n{df_json_path}")
                print(f"----------------------------END:{indx}---------------------------------------")
                merged_df = pd.concat([df, df_tmp], ignore_index=True)
                df = merged_df
                indx = indx + 1
    return df

def main(binary_dir, csv_output_dir, is_malware):
    eprint("----------ELF_Extractor_From_Files.err----------START----------")
    df_total = elf_extractor_runner(binary_dir, csv_output_dir, is_malware)
    print(df_total['sha256_hash'])
    print(df_total['label'].value_counts())
    print(df_total.shape)
    df_total.to_json("total_dataset.json", orient='records', indent=4)
    df_total.to_csv("total_dataset.csv", index=False)
    eprint("----------ELF_Extractor_From_Files.err---------- END ----------")

if __name__ == "__main__":
    print("[" + __file__ + "]'s last modified: %s" % time.ctime(os.path.getmtime(__file__)))
    # Check if a parameter is provided
    if len(sys.argv) == 3:
        in_dir = sys.argv[1]
        if not os.path.exists(in_dir):
            print(f"Directory: '{in_dir}' does not exist.")
            exit()
        print(f"\n\nBinary Directory:\t\t{in_dir}")

        out_dir = sys.argv[2]
        if not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)
        print(f"CSV Files will save:\t{out_dir}")
        main(in_dir, out_dir, False)
    else:
        print("No input directory and output directory provided.")