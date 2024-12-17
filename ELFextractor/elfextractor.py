import sys
import os
import os.path, time
import lief
import pandas as pd
import hashlib
from datetime import datetime

# Initialize a dictionary to hold the ELF data
elf_data = {}


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def is_binary(fpath):
    return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

def shannon_entropy(data):
    # 256 different possible values
    possible = dict(((chr(x), 0) for x in range(0, 256)))

    for byte in data:
        possible[chr(byte)] += 1

    data_len = len(data)
    entropy = 0.0

    # compute
    for i in possible:
        if possible[i] == 0:
            continue

        p = float(possible[i] / data_len)
        entropy -= p * math.log(p, 2)
    return entropy

# Extract ELF header information
def extract_elf_header_info(elf_file):
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
    elf_data.update(header_info)

def extract_elf_section_info(elf_file):
    # Extract section information
    esections = elf_file.sections
    sections_info = {
        "Number of Sections": len(elf_file.sections)
    }
    for section in esections:
        sections_info[f"{section.name}_type"] = section.type
        sections_info[f"{section.name}_flags"] = section.flags
        sections_info[f"{section.name}_virtual_address"] = hex(section.virtual_address)
        sections_info[f"{section.name}_offset"] = section.offset
        sections_info[f"{section.name}_size"] = section.size
        sections_info[f"{section.name}_entropy"] = section.entropy

    # Add section information to the ELF data dictionary
    elf_data.update(sections_info)

def extract_elf_segment_info(elf_file):
    # Extract segments information
    esegments = elf_file.segments
    segments_info = {
        "Number of Segments": len(elf_file.segments)
    }
    iseg = 0
    for segment in esegments:
        iseg += 1
        segments_info[f"{iseg}_segment_type"] = segment.type,
        segments_info[f"{iseg}_segment_flags"] = segment.flags,
        segments_info[f"{iseg}_segment_virtual_address"] = hex(segment.virtual_address),
        segments_info[f"{iseg}_segment_physical_address"] = hex(segment.physical_address),
        segments_info[f"{iseg}_segment_file_offset"] = hex(segment.file_offset),
        segments_info[f"{iseg}_segment_virtual_size"] = hex(segment.virtual_size),
        #segments_info[f"{iseg}_segment_file_size"] = segment.file_size

    # Add section information to the ELF data dictionary
    elf_data.update(segments_info)


def extract_elf_import_info(elf_file):
    # Extract import table information
    dynamic_entries = elf_file.dynamic_entries
    import_info = { }

    iimp = 0
    for entry in dynamic_entries:
        if entry.tag == 1:
            iimp += 1
            import_info[f"{iimp}_import_name"] = entry.name

    # Add section information to the ELF data dictionary
    elf_data.update(import_info)

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



# Extract ELF dynamic entries and symbols (equivalent to imports/exports)
def extract_elf_dynamic_info(elf):
    # Dynamic entries (imports)
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
            if not filename.endswith(extensions):
                eprint("this file is not executable: ", filename)
                continue
            else:
                df_header  = pd.DataFrame()
                df_section = pd.DataFrame()
                df_segment = pd.DataFrame()
                df_import  = pd.DataFrame()
                df_export  = pd.DataFrame()

                full_file_path = os.path.join(r, filename)
                sha256_hash = hashlib.sha256()
                with open(full_file_path, "rb") as f:
                    # Read and update hash string value in blocks of 4K
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(byte_block)
                filename = sha256_hash.hexdigest()
                df.at[indx, 'sha256_hash'] = filename
                print("-------------------------------------------------------------------")
                now = datetime.now()
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
                extract_elf_header_info(elf)
                #extract_elf_section_info(elf)
                #extract_elf_segment_info(elf)
                #extract_elf_import_info(elf)
                #extract_elf_export_info(elf)

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