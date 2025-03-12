import os
import json
import sys
import argparse
import hashlib
import pandas as pd
import configparser
import multiprocessing
from concurrent.futures import ThreadPoolExecutor

import xml.etree.ElementTree as ET

from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_E_TYPE, ENUM_E_MACHINE

def is_elf_file(file_path, verbose=False):
    """Check if a file is an ELF file by reading the magic number."""
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(4)
            if magic != b'\x7fELF' and verbose:
                print(f"Skipping {file_path}: Not an ELF file (magic: {magic.hex()})")
            return magic == b'\x7fELF'
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
    """Extract ELF header information, including file name and SHA-256."""
    if verbose:
        print(f"Parsing {file_path}")
    try:
        with open(file_path, 'rb') as f:
            elf_file = ELFFile(f)
            elf_header = elf_file.header

            header_info = {
                'file_name': os.path.basename(file_path),
                'file_sha256': calculate_sha256(file_path),
                'e_ident': {
                    'EI_MAG': ''.join([f'{c:02X}' for c in elf_header['e_ident']['EI_MAG']]),
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

def read_config(config_path, verbose=False):
    """Read settings from a .conf file."""
    config = configparser.ConfigParser()
    settings = {
        'path': None,
        'threads': None,
        'verbose': False
    }

    if not os.path.isfile(config_path):
        if verbose:
            print(f"Config file {config_path} does not exist.")
        return settings

    try:
        config.read(config_path)
        if 'Settings' not in config:
            if verbose:
                print(f"Config file {config_path} missing [Settings] section.")
            return settings

        # Read path
        if config['Settings'].get('path'):
            settings['path'] = config['Settings']['path'].strip()
            if verbose and not (os.path.isfile(settings['path']) or os.path.isdir(settings['path'])):
                print(f"Warning: Config path '{settings['path']}' is invalid; will fall back to command-line.")

        # Read threads
        try:
            if config['Settings'].get('threads'):
                settings['threads'] = int(config['Settings']['threads'])
                if settings['threads'] < 1:
                    if verbose:
                        print("Warning: Config threads < 1; will fall back to command-line or default.")
                    settings['threads'] = None
        except ValueError:
            if verbose:
                print("Warning: Invalid threads value in config; will fall back to command-line or default.")
            settings['threads'] = None

        # Read verbose
        if config['Settings'].get('verbose'):
            verbose_str = config['Settings']['verbose'].strip().lower()
            settings['verbose'] = verbose_str == 'true'

        if verbose:
            print(f"Loaded config: path={settings['path']}, threads={settings['threads']}, verbose={settings['verbose']}")
    except Exception as e:
        if verbose:
            print(f"Error reading config file {config_path}: {e}")
    return settings

def main():
    parser = argparse.ArgumentParser(description="Extract ELF header information and save as JSON/XML/CSV using LIEF.")
    parser.add_argument("path", nargs='?', default=None, help="Path to a single ELF file or a directory containing ELF files.")
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
    parser.add_argument(
        "-c", "--config",
        type=str,
        default=None,
        help="Path to a .conf file specifying path, threads, and verbose settings."
    )
    args = parser.parse_args()

    # Initialize settings
    input_path = args.path
    num_threads = max(1, args.threads)
    verbose = args.verbose

    # Read config file if provided
    if args.config:
        config_settings = read_config(args.config, verbose)
        # Override with config values if valid
        input_path = config_settings['path'] if config_settings['path'] else input_path
        num_threads = max(1, config_settings['threads']) if config_settings['threads'] is not None else num_threads
        verbose = config_settings['verbose'] or verbose  # Config verbose=true overrides CLI --verbose

    # Validate input path
    if not input_path:
        print("Error: No input path provided (via command-line or config).")
        sys.exit(1)

    # Process file or directory
    if os.path.isfile(input_path):
        process_single_file(input_path, verbose=verbose)
    elif os.path.isdir(input_path):
        process_directory(input_path, num_threads, verbose)
    else:
        print(f"Error: '{input_path}' is neither a valid file nor a directory.")
        sys.exit(1)

# pip show pyelftools
# pip show pandas

# pip install pyelftools
# pip install pandas

# python3 header_extractor_wpyelftools.py <elf_file_or_directory> ...
if __name__ == "__main__":
    main()