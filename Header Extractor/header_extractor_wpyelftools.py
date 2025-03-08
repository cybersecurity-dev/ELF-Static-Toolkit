import os
import json
import sys
import argparse
import hashlib
import multiprocessing
from concurrent.futures import ThreadPoolExecutor

import xml.etree.ElementTree as ET
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_E_TYPE, ENUM_E_MACHINE

def is_elf_file(file_path):
    """Check if a file is an ELF file by reading the magic number."""
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(4)
            return magic == b'\x7fELF'
    except:
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

def extract_elf_header(file_path):
    """Extract ELF header information from a given file."""
    try:
        with open(file_path, 'rb') as f:
            elf_file = ELFFile(f)
            elf_header = elf_file.header

            # Extract relevant header information
            header_info = {
                'file_name': os.path.basename(file_path),
                'file_sha256': calculate_sha256(file_path),
                'e_ident': {
                    'EI_MAG': ''.join([f'{c:02X}' for c in elf_header['e_ident']['EI_MAG']]),  # Hex representation
                    'EI_CLASS': elf_header['e_ident']['EI_CLASS'],
                    'EI_DATA': elf_header['e_ident']['EI_DATA'],
                    'EI_VERSION': elf_header['e_ident']['EI_VERSION'],
                    'EI_OSABI': elf_header['e_ident']['EI_OSABI'],
                    'EI_ABIVERSION': elf_header['e_ident']['EI_ABIVERSION']
                },
                'e_type': ENUM_E_TYPE.get(elf_header['e_type'], 'Unknown'),
                'e_machine': ENUM_E_MACHINE.get(elf_header['e_machine'], 'Unknown'),
                'e_version': elf_header['e_version'],
                'e_entry': hex(elf_header['e_entry']),
                'e_phoff': hex(elf_header['e_phoff']),
                'e_shoff': hex(elf_header['e_shoff']),
                'e_flags': hex(elf_header['e_flags']),
                'e_ehsize': elf_header['e_ehsize'],
                'e_phentsize': elf_header['e_phentsize'],
                'e_phnum': elf_header['e_phnum'],
                'e_shentsize': elf_header['e_shentsize'],
                'e_shnum': elf_header['e_shnum'],
                'e_shstrndx': elf_header['e_shstrndx']
            }
            return header_info
    except Exception as e:
        print(f"Error reading ELF file {file_path}: {e}")
        return None

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
def process_single_file(file_path, output_dir=None):
    """Process a single ELF file and save its header info."""
    if not is_elf_file(file_path):
        print(f"{file_path} is not a valid ELF file.")
        return

    header_info = extract_elf_header(file_path)
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
    else:
        print(f"Failed to extract header from {file_path}.")

def process_directory(dir_path, num_threads):
    """Process all ELF files in a directory using multiple threads and save results in elf_extracted subdirectory."""
    if not os.path.isdir(dir_path):
        print(f"{dir_path} is not a valid directory.")
        return

    # Create output directory
    output_dir = os.path.join(dir_path, 'elf_extracted')
    try:
        os.makedirs(output_dir, exist_ok=True)
        print(f"Created output directory: {output_dir}")
    except Exception as e:
        print(f"Error creating output directory {output_dir}: {e}")
        return

    # Collect ELF files
    elf_files = [
        os.path.join(dir_path, file_name)
        for file_name in os.listdir(dir_path)
        if os.path.isfile(os.path.join(dir_path, file_name)) and is_elf_file(os.path.join(dir_path, file_name))
    ]

    if not elf_files:
        print(f"No ELF files found in {dir_path}.")
        return

    print(f"Found {len(elf_files)} ELF files to process with {num_threads} threads.")

    # Process files using ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(process_single_file, file_path, output_dir)
            for file_path in elf_files
        ]
        # Wait for all tasks to complete
        for future in futures:
            try:
                future.result()
            except Exception as e:
                print(f"Error in thread: {e}")

def main():
    parser = argparse.ArgumentParser(description="Extract ELF header information and save as JSON/XML.")
    parser.add_argument("path", help="Path to a single ELF file or a directory containing ELF files.")
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=min(multiprocessing.cpu_count(), 4),
        help="Number of threads to use for directory processing (default: min(CPU count, 4))."
    )
    args = parser.parse_args()

    input_path = args.path
    num_threads = max(1, args.threads)  # Ensure at least 1 thread

    if os.path.isfile(input_path):
        process_single_file(input_path)
    elif os.path.isdir(input_path):
        process_directory(input_path, num_threads)
    else:
        print(f"Error: '{input_path}' is neither a valid file nor a directory.")
        sys.exit(1)
# pip install pyelftools
# python3 header_extractor_wpyelftools.py <elf_file_or_directory> ...
if __name__ == "__main__":
    main()