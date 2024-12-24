import sys
import os
import os.path, time
import lief
import pandas as pd
import hashlib
import datetime
import subprocess
import math

# Initialize a dictionary to hold the ELF data
elf_data = {}
initflag = True

def clear_log_file(log_file_path):
    try:
        with open(log_file_path, "w"):  # Open in write mode, which truncates the file
            pass  # No need to write anything
        print(f"Log file '{log_file_path}' cleared.")
    except Exception as e:
        print(f"Error clearing log file: {e}")

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

def get_segment_flags(segment):
    flags = segment.flags.name
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


def get_abi_version(elf):
    """Extracts the Build ID from an ELF binary using LIEF."""
    for note in elf.notes:
        if note.name == "GNU" and note.type == lief.ELF.NOTE_TYPES.ABI_TAG:
            abi_version = (note.description[4], note.description[8], note.description[12])
            note_owner = note.name
            note_abi_version = '.'.join(map(str, abi_version[:3]))
            return note_owner, note_abi_version
    return None, None

def get_build_id(elf):
    """Extracts the ABI tag from an ELF binary using LIEF."""
    for note in elf.notes:
        if  note.name == "GNU" and note.type == lief.ELF.NOTE_TYPES.BUILD_ID:
            note_build_id = ''.join(f"{byte:02x}" for byte in note.description) if note.description else "None"
            #note_build_id = note.description.hex()
            note_owner = note.name
            return note_owner, note_build_id
    return None, None

def extract_elf_file_notes_info(elf):
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
    return owner, build_id, abi_version

# Extract ELF header information ##Checked: readelf  --file-header sample.elf
def extract_elf_file_header_info(elf_file):
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
    print(header_info)
    elf_data.update(header_info)

#Section Headers  ##Checked  readelf --section-headers sample.elf
def extract_elf_section_headers_info(elf_file):
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

    #print(sections_info)
    for key, value in sections_info.items():
        print(key, value)
    # Add section information to the ELF data dictionary
    elf_data.update(sections_info)

#Program Headers/Segment ##Checked  readelf --program-headers sample.elf
def extract_elf_program_headers_info(elf_file):
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
        #segments_info[f"{Program_Headers_Type}_segment_flags"] = segment.flags.name
        flags = []
        if segment.has(lief.ELF.SEGMENT_FLAGS.R):
            flags.append("R")
        if segment.has(lief.ELF.SEGMENT_FLAGS.W):
            flags.append("W")
        if segment.has(lief.ELF.SEGMENT_FLAGS.X):
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
    for key, value in segments_info.items():
        print(key, value)
    # Add section information to the ELF data dictionary
    elf_data.update(segments_info)
 
# Extract segment-to-section mapping ##Checked  readelf --program-headers sample.elf
def extract_segment_to_section_mapping(elf_file):
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
    
    for key, value in segment_to_section_mapping_data.items():
        print(key, value)
    #df_segment_to_section_mapping_data = pd.DataFrame(segment_to_section_mapping_data, index=[0])
    elf_data.update(segment_to_section_mapping_data)

def extract_elf_export_info(elf_file):
    # Extract export table information
    exported_symbols = elf_file.exported_symbols
    export_info = { }

    iexp = 0
    for symbol in exported_symbols:
        iexp += 1
        export_info[f"{iexp}_export_name"] = symbol.name

    # Add section information to the ELF data dictionary
    elf_data.update(export_info)

def extract_elf_shared_lib_info(elf_file):
    # Extract shared libraries from the dynamic section
    shared_libraries = []
    eentry = elf_file.dynamic_entries
    for entry in eentry:
        #if entry.tag == lief.ELF.DYNAMIC_TAG.NEEDED:  # Only needed shared libraries
        if entry.tag.name == "NEEDED":  # Tag 1 corresponds to NEEDED
            shared_libraries.append({
                "Tag": str(entry.tag.name),  # Dynamic tag type
                "Type": "NEEDED",
                "Shared Library": entry.name
            })
    df_shared_libraries = pd.DataFrame(shared_libraries)
    print(df_shared_libraries)

# Extract ELF dynamic entries and symbols (equivalent to imports/exports)
def extract_elf_dynamic_info(elf_file):
   # Extract dynamic symbols (used for runtime imports)
    dynamic_symbols = []
    for symbol in elf_file.dynamic_symbols:
        dynamic_symbols.append({
            "Name": symbol.name,
            "Value": hex(symbol.value),
            "Size": symbol.size,
            "Type": symbol.type.name if symbol.type else "UNKNOWN",
            "Binding": symbol.binding.name if symbol.binding else "UNKNOWN",
            "Visibility": symbol.visibility.name if symbol.visibility else "UNKNOWN",
            "Ndx": str(symbol.shndx)  # Section index (Ndx) field
        })

    df_dynamic_symbols = pd.DataFrame(dynamic_symbols)
    print(df_dynamic_symbols)

# Extract ELF dynamic entries and symbols (equivalent to imports/exports)
def extract_elf_dynamic_info2(elf):
    # Extract dynamic symbols (used for runtime imports)
    dynamic_info = []
    for dynamic_entry in elf.dynamic_entries:
        dynamic_info.append(f"Tag: {dynamic_entry.tag}, Value: {dynamic_entry.value}")
    
    elf_data["Dynamic Entries"] = dynamic_info if dynamic_info else "None"
    
    # Exported functions (symbols)
    exported_symbols = []
    for symbol in elf.symbols:
        if symbol.exported:
            exported_symbols.append(f"Symbol: {symbol.name}, Value: {symbol.value}")
    
    elf_data["Exported Symbols"] = exported_symbols if exported_symbols else "None"
    
    # Imported functions (symbols)
    imported_symbols = []
    for symbol in elf.imported_symbols:
        imported_symbols.append(f"Symbol: {symbol.name}, Value: {symbol.value}")
    
    elf_data["Imported Symbols"] = imported_symbols if imported_symbols else "None"


def elf_extractor_runner(binary_dir, csv_output_dir, is_malware):
    global elf_data

    # hash_list = []
    indx = 0
    df = pd.DataFrame()
    extensions = ("elf")

    for r, d, f in os.walk(binary_dir):
        for filename in f:
            #if not filename.endswith(extensions):
                #eprint("this file is not executable: ", filename)
                #continue
            full_file_path = os.path.join(r, filename)
            elf_type = get_elf_type(full_file_path)
            if elf_type != "ET_EXEC":
                eprint(f"File path:{full_file_path}\nELF Type:{elf_type}")
                continue
            else:
                print(f"File path:{full_file_path}\nELF Type:{elf_type}")
                df_header  = pd.DataFrame()
                df_section = pd.DataFrame()
                df_segment = pd.DataFrame()
                df_import  = pd.DataFrame()
                df_export  = pd.DataFrame()
                
                sha256_hash = hashlib.sha256()
                with open(full_file_path, "rb") as f:
                    # Read and update hash string value in blocks of 4K
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(byte_block)
                filename = sha256_hash.hexdigest()
                df.at[indx, 'sha256_hash'] = filename
                print("-------------------------------------------------------------------")
                now = datetime.datetime.now()
                date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
                print("File operation started at: ", date_time)
                print("Next hash file::", df.at[indx, 'sha256_hash'])
                print("Full_file_path::", full_file_path)
                
                print("-------------------------------------------------------------------")
                if indx % 100 == 0:
                    print("Hundred Element Count:", indx)
                
                elf_data = {}

                elf = lief.parse(full_file_path)

                # Call the extraction functions
                #extract_elf_header_info(elf)
                #extract_elf_section_info(elf)
                #extract_elf_segment_info(elf)
                #extract_segment_to_section_mapping(elf)
                #extract_elf_import_info(elf)
                #extract_elf_export_info(elf)
                #extract_elf_dynamic_info(elf)
                #extract_elf_shared_lib_info(elf)
                elf_notes_owner, elf_notes_build_id, elf_notes_abi_version = extract_elf_file_notes_info(elf)


                # Convert the ELF data dictionary into a DataFrame
                df = pd.DataFrame([elf_data])
                df_csv_path = f"{csv_output_dir}/{filename}.csv"
                df_pkl_path = f"{csv_output_dir}/{filename}.pkl"             

                # Save DataFrame as CSV
                df.to_csv(df_csv_path, index=False)
                print(f"{filename} information saved into csv:\n{df_csv_path}")
                
                # Save DataFrame as pickle (.pkl)
                df.to_pickle(df_pkl_path)
                print(f"{filename} information saved into pkl:\n{df_pkl_path}")

                df.at[indx, 'label'] = int(1) if is_malware else int(0)
                indx = indx + 1
    return df

def main(binary_dir, csv_output_dir, is_malware):
    eprint("----------ELF_Extractor_From_Files.err----------START----------")
    elf_extractor_runner(binary_dir, csv_output_dir, is_malware)
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