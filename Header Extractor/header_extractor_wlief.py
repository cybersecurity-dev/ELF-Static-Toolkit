import os
import json
import sys
import argparse
import hashlib
import pandas as pd
import lief
import multiprocessing
from concurrent.futures import ThreadPoolExecutor

import xml.etree.ElementTree as ET

def is_elf_file(file_path, verbose=False):
    """Check if a file is an ELF file using LIEF."""
    try:
        parsed = lief.parse(file_path)
        is_elf = parsed is not None and type(parsed) is lief.ELF.Binary
        if not is_elf and verbose:
            print(f"Skipping {file_path}: Not an ELF file")
        return is_elf
    except Exception as e:
        if verbose:
            print(f"Skipping {file_path}: Cannot read file ({e})")
        return False

def calculate_sha256(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error calculating SHA-256 for {file_path}: {e}")
        return None

def extract_elf_header(file_path, verbose=False):
    """Extract ELF header information using LIEF, including file name and SHA-256."""
    if verbose:
        print(f"Parsing {file_path}")
    try:
        elf = lief.parse(file_path)
        if not elf:
            if verbose:
                print(f"Failed to parse {file_path}: Invalid ELF file")
            return None

        header = elf.header
        header_info = {
            'file_name': os.path.basename(file_path),
            'file_sha256': calculate_sha256(file_path),
            'e_ident': {
                'EI_MAG': ''.join([f'{c:02X}' for c in header.identity]),  # First 4 bytes
                'EI_CLASS': str(header.identity_class),  # e.g., ELF_CLASS_64
                'EI_DATA': str(header.identity_data),    # e.g., ELFDATA2LSB
                'EI_VERSION': header.identity_version,   # Typically 1 #EI_VERSION (Identification Version)
                'EI_OSABI': str(header.identity_os_abi), # e.g., ELFOSABI_SYSV
                'EI_ABIVERSION': header.identity_abi_version
            },
            'e_type': str(header.file_type),           # e.g., ET_EXEC
            'e_machine': str(header.machine_type),     # e.g., EM_X86_64
            
             # Note: LIEF 0.16.4 does not expose e_version directly; 
            'e_version': header.identity_version, # using identity_version as proxy #e_version (Object File Version)
            
            'e_entry': hex(header.entrypoint),
            'e_phoff': hex(header.program_header_offset),
            'e_shoff': hex(header.section_header_offset),
            'e_flags': hex(header.processor_flag),
            'e_ehsize': header.header_size,
            'e_phentsize': header.program_header_size,
            'e_phnum': header.numberof_segments,
            'e_shentsize': header.section_header_size,
            'e_shnum': header.numberof_sections,
            'e_shstrndx': header.section_name_table_idx
        }
        return header_info
    except Exception as e:
        if verbose:
            print(f"Failed to parse {file_path}: {e}")
        return None

def flatten_header_info(header_info):
    """Flatten header_info dictionary for CSV output."""
    if not header_info:
        return {}
    flat_info = {
        'file_name': header_info.get('file_name'),
        'file_sha256': header_info.get('file_sha256'),
        'EI_MAG': header_info['e_ident'].get('EI_MAG'),
        'EI_CLASS': header_info['e_ident'].get('EI_CLASS'),
        'EI_DATA': header_info['e_ident'].get('EI_DATA'),
        'EI_VERSION': header_info['e_ident'].get('EI_VERSION'),
        'EI_OSABI': header_info['e_ident'].get('EI_OSABI'),
        'EI_ABIVERSION': header_info['e_ident'].get('EI_ABIVERSION'),
        'e_type': header_info.get('e_type'),
        'e_machine': header_info.get('e_machine'),
        'e_version': header_info.get('e_version'),
        'e_entry': header_info.get('e_entry'),
        'e_phoff': header_info.get('e_phoff'),
        'e_shoff': header_info.get('e_shoff'),
        'e_flags': header_info.get('e_flags'),
        'e_ehsize': header_info.get('e_ehsize'),
        'e_phentsize': header_info.get('e_phentsize'),
        'e_phnum': header_info.get('e_phnum'),
        'e_shentsize': header_info.get('e_shentsize'),
        'e_shnum': header_info.get('e_shnum'),
        'e_shstrndx': header_info.get('e_shstrndx')
    }
    return flat_info

def save_to_json(data, output_file):
    """Save data to a JSON file."""
    try:
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"JSON saved to {output_file}")
    except Exception as e:
        print(f"Error saving JSON to {output_file}: {e}")

def dict_to_xml(data, root_name):
    """Convert dictionary to XML structure."""
    def build_element(parent, key, value):
        if isinstance(value, dict):
            element = ET.SubElement(parent, key)
            for k, v in value.items():
                build_element(element, k, v)
        else:
            element = ET.SubElement(parent, key)
            element.text = str(value)

    root = ET.Element(root_name)
    for key, value in data.items():
        build_element(root, key, value)
    return root

def save_to_xml(data, output_file):
    """Save data to an XML file."""
    try:
        tree = dict_to_xml(data, 'ELFHeader')
        xml_string = ET.tostring(tree, encoding='unicode', method='xml')
        xml_string = '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_string
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(xml_string)
        print(f"XML saved to {output_file}")
    except Exception as e:
        print(f"Error saving XML to {output_file}: {e}")

def save_to_csv(header_list, output_file, verbose=False):
    """Save list of header info dictionaries to a CSV file."""
    try:
        if not header_list:
            print(f"No data to save to CSV: {output_file}")
            return
        flat_data = [flatten_header_info(header) for header in header_list]
        df = pd.DataFrame(flat_data)
        df.to_csv(output_file, index=False)
        print(f"CSV saved to {output_file}")
        if verbose:
            print(f"CSV dimensions: {len(df)} rows, {len(df.columns)} columns")
    except Exception as e:
        print(f"Error saving CSV to {output_file}: {e}")

def process_single_file(file_path, output_dir=None, verbose=False):
    """Process a single ELF file and save its header info."""
    if not is_elf_file(file_path, verbose):
        return None

    header_info = extract_elf_header(file_path, verbose)
    if header_info:
        file_name = os.path.basename(file_path)
        if output_dir:
            json_output = os.path.join(output_dir, f"{file_name}.json")
            xml_output = os.path.join(output_dir, f"{file_name}.xml")
        else:
            json_output = f"{file_name}.json"
            xml_output = f"{file_name}.xml"

        save_to_json(header_info, json_output)
        save_to_xml(header_info, xml_output)
        return header_info
    return None

def process_directory(dir_path, num_threads, verbose=False):
    """Process all ELF files in a directory using multiple threads."""
    if not os.path.isdir(dir_path):
        print(f"{dir_path} is not a valid directory.")
        return

    output_dir = os.path.join(dir_path, 'elf_extracted')
    try:
        os.makedirs(output_dir, exist_ok=True)
        print(f"Created output directory: {output_dir}")
    except Exception as e:
        print(f"Error creating output directory {output_dir}: {e}")
        return

    elf_files = [
        os.path.join(dir_path, file_name)
        for file_name in os.listdir(dir_path)
        if os.path.isfile(os.path.join(dir_path, file_name))
    ]

    if not elf_files:
        print(f"No files found in {dir_path}.")
        return

    if verbose:
        print(f"Scanning {len(elf_files)} files in {dir_path}...")

    header_list = []
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(process_single_file, file_path, output_dir, verbose)
            for file_path in elf_files
        ]
        for future in futures:
            try:
                result = future.result()
                if result:
                    header_list.append(result)
            except Exception as e:
                if verbose:
                    print(f"Thread error: {e}")

    if header_list:
        print(f"Processed {len(header_list)} ELF files.")
        csv_output = os.path.join(output_dir, 'all_header_feature.csv')
        save_to_csv(header_list, csv_output, verbose)
    elif verbose:
        print("No ELF files were successfully processed.")

def main():
    parser = argparse.ArgumentParser(description="Extract ELF header information and save as JSON/XML/CSV using LIEF.")
    parser.add_argument("path", help="Path to a single ELF file or a directory containing ELF files.")
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=min(multiprocessing.cpu_count(), 4),
        help="Number of threads to use for directory processing (default: min(CPU count, 4))."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output: list parsed files, non-ELF files, and CSV dimensions."
    )
    args = parser.parse_args()

    input_path = args.path
    num_threads = max(1, args.threads)
    verbose = args.verbose

    if os.path.isfile(input_path):
        process_single_file(input_path, verbose=verbose)
    elif os.path.isdir(input_path):
        process_directory(input_path, num_threads, verbose)
    else:
        print(f"Error: '{input_path}' is neither a valid file nor a directory.")
        sys.exit(1)

# pip show lief
# pip show pandas

# pip install lief
# pip install pandas

# python3 header_extractor_wlief.py <elf_file_or_directory> ...
if __name__ == "__main__":
    main()