import os
import time
import pandas as pd
import sys
import lief
import shutil
import csv

from elf_metadata import calculate_sha256 
from elf_metadata import is_elf_file
from elf_metadata import detect_architecture
from elf_metadata import extract_elf_file_notes_info

#FIRST PART - ELF header
from elf_header import extract_elf_file_header_info

#SECOND PART - File data
#1 - Program Headers or Segments
#2 - Section Headers or Sections
#Data

#1 - Program Headers or Segments
from elf_program_header import extract_elf_program_headers_info
from elf_program_header import extract_segment_to_section_mapping
#2 - Section Headers or Sections
from elf_sections_header import extract_elf_section_headers_info



from elf_version_info import extract_elf_file_version_needs

from elf_export_table import extract_elf_export_info
from elf_import_table import extract_elf_import_info


from elf_dynamic_symbols import extract_elf_dynamic_section_info
from elf_dynamic_symbols import extract_elf_dynsym_symbol_table

def copy_processed_files(fpath, new_fpath, new_filename) -> bool:
    destination_path = os.path.join(new_fpath, new_filename)

    if not os.path.exists(destination_path):
        shutil.copy2(fpath, destination_path)
        print(f"File '{fpath}' copied to '{destination_path}'")
        return True
    else:
        print(f"File '{destination_path}' already exists. Skipping copy.")
        return False

def elf_extractor_runner(binary_dir, output_dir, is_malware=False):
    indx = 0
    df_L1 = pd.DataFrame()
    df_L2 = pd.DataFrame()
    df_L3 = pd.DataFrame()

    for r, d, f in os.walk(binary_dir):
        for filename in f:
            full_file_path = os.path.join(r, filename)
            if os.path.islink(full_file_path):
                print(full_file_path + " is a symbolic link")
            if not os.path.exists(full_file_path):
                print(full_file_path + " is broken")
                continue
            if not is_elf_file(full_file_path):
                print(f"File path:{full_file_path}\tis not ELF")
                continue
            if detect_architecture(full_file_path) not in ("Intel 80386", "Intel x86-64"):
                print(f"ELF is not Intel Architecture:{full_file_path}")
                continue
            
            sha256_id = calculate_sha256(full_file_path)
            copy_processed_files(full_file_path, f"{output_dir}/ELF/", sha256_id)
            elf_parse_result = {'sha256_hash': sha256_id, 'filename': filename}

            elf = lief.parse(full_file_path)
            
            #--------------------------------------------------------------------------------------------L1
            #l1 - METADATA INFORMATION l1
            #print(extract_elf_file_header_info(elf)) #checked
            elf_parse_result.update(extract_elf_file_header_info(elf.header, full_file_path))
            #print(elf_parse_result)
            
            #print(extract_elf_file_version_needs(elf))
            elf_parse_result.update(extract_elf_file_version_needs(elf))
            #print(elf_parse_result)
            
            
            #print(extract_elf_file_notes_info(elf, full_file_path))
            elf_parse_result.update(extract_elf_file_notes_info(elf, full_file_path))
            #print(elf_parse_result)


            df_tmp_L1 = pd.DataFrame([elf_parse_result])
            df_tmp_L1.to_csv(f"{output_dir}/ELF_JSON/L1_{sha256_id}.csv", index=False, quoting=csv.QUOTE_NONNUMERIC)
            df_tmp_L1.to_json(f"{output_dir}/ELF_JSON/L1_{sha256_id}.json", orient='records', indent=4)
            
            merged_df_L1 = pd.concat([df_L1, df_tmp_L1], ignore_index=True)
            df_L1 = merged_df_L1
            #--------------------------------------------------------------------------------------------L1


            
            #--------------------------------------------------------------------------------------------L2
            #l2 - 
            #print(extract_elf_program_headers_info(elf, full_file_path))
            elf_parse_result.update(extract_elf_program_headers_info(elf.segments, full_file_path))
            #print(elf_parse_result)
            
            
            #print(extract_segment_to_section_mapping(elf, full_file_path))
            elf_parse_result.update(extract_segment_to_section_mapping(elf.segments, elf.sections, full_file_path))
            #print(elf_parse_result)

            #print(extract_elf_section_headers_info(elf, full_file_path))
            elf_parse_result.update(extract_elf_section_headers_info(elf.sections, full_file_path))
            #print(elf_parse_result)
            df_tmp_L2 = pd.DataFrame([elf_parse_result])
            df_tmp_L2.to_csv(f"{output_dir}/ELF_JSON/L2_{sha256_id}.csv", index=False, quoting=csv.QUOTE_NONNUMERIC)
            df_tmp_L2.to_json(f"{output_dir}/ELF_JSON/L2_{sha256_id}.json", orient='records', indent=4)
            
            merged_df_L2 = pd.concat([df_L2, df_tmp_L2], ignore_index=True)
            df_L2 = merged_df_L2
            #--------------------------------------------------------------------------------------------L2
            
            
            #--------------------------------------------------------------------------------------------L3
            #l3 - EXPORT/IMPORT SECTION
            #print(extract_elf_export_info(elf, full_file_path))
            elf_parse_result.update(extract_elf_export_info(elf,full_file_path))
            #print(elf_parse_result)

            #print(extract_elf_import_info(elf, full_file_path))
            elf_parse_result.update(extract_elf_import_info(elf,full_file_path))
            #print(elf_parse_result)
            
            #print(extract_elf_shared_lib_info(elf))
            elf_parse_result.update(extract_elf_dynamic_section_info(elf))
            #print(elf_parse_result)

            #print(extract_elf_dynamic_info(elf))
            elf_parse_result.update(extract_elf_dynsym_symbol_table(elf, full_file_path))
            #print(elf_parse_result)
            #--------------------------------------------------------------------------------------------l3
            
            
            df_tmp_L3 = pd.DataFrame([elf_parse_result])
            df_tmp_L3.to_csv(f"{output_dir}/ELF_JSON/L3_{sha256_id}.csv", index=False, quoting=csv.QUOTE_NONNUMERIC)
            df_tmp_L3.to_json(f"{output_dir}/ELF_JSON/L3_{sha256_id}.json", orient='records', indent=4)

            merged_df_L3 = pd.concat([df_L3, df_tmp_L3], ignore_index=True)
            df_L3 = merged_df_L3
    return df_L1, df_L2, df_L3

def main(binary_dir, output_dir, is_malware):
    postfix = f"" 
    if is_malware:
        postfix = f"Malware"
    else:
        postfix = f"Benign"
    dfL1, dfL2, dfL3 = elf_extractor_runner(binary_dir, output_dir, is_malware)
    dfL1.to_csv(f"{output_dir}/L1_{postfix}.csv", index=False, quoting=csv.QUOTE_NONNUMERIC)
    dfL2.to_csv(f"{output_dir}/L2_{postfix}.csv", index=False, quoting=csv.QUOTE_NONNUMERIC)
    dfL3.to_csv(f"{output_dir}/L3_{postfix}.csv", index=False, quoting=csv.QUOTE_NONNUMERIC)


if __name__ == "__main__":
    print("[" + __file__ + "]'s last modified: %s" % time.ctime(os.path.getmtime(__file__)))
    # Check if a parameter is provided
    if len(sys.argv) == 4:
        in_dir = sys.argv[1]
        if not os.path.exists(in_dir):
            print(f"Directory: '{in_dir}' does not exist.")
            exit()
        print(f"\n\nBinary Directory:\t\t{in_dir}")

        out_dir = sys.argv[2]
        if not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)
        is_dataset_malware = bool(sys.argv[2])
        print(f"CSV Files will save:\t{out_dir}")
        main(in_dir, out_dir, is_dataset_malware)
    else:
        print("No input directory and output directory provided.")