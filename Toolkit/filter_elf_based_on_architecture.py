import os
import sys
import argparse
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

from concurrent.futures import ThreadPoolExecutor
import threading
import shutil

def get_elf_architecture(elf_file):
    """Determine ELF file architecture."""
    try:
        with open(elf_file, 'rb') as f:
            elf = ELFFile(f)
            machine = elf.header['e_machine']
            
            # x86 and x86_64
            if machine == 'EM_386' or machine == 'EM_X86_64':
                return 'intel'
            # ARM
            elif machine == 'EM_ARM' or machine == 'EM_AARCH64':
                return 'arm'
            # MIPS
            elif machine == 'EM_MIPS':
                return 'mips'
            else:
                return None
    except ELFError:
        return None
    except Exception as e:
        print(f"Error processing {elf_file}: {str(e)}")
        return None

def create_subdirs(base_dir):
    """Create architecture-specific subdirectories."""
    subdirs = {
        'intel': os.path.join(base_dir, 'intel'),
        'arm': os.path.join(base_dir, 'arm'),
        'mips': os.path.join(base_dir, 'mips')
    }
    
    for subdir in subdirs.values():
        os.makedirs(subdir, exist_ok=True)
    
    return subdirs

def process_file(filepath, subdirs, lock):
    """Process a single file and copy to appropriate subdirectory."""
    filename = os.path.basename(filepath)
    arch = get_elf_architecture(filepath)
    
    if arch:
        dest_dir = subdirs[arch]
        dest_path = os.path.join(dest_dir, filename)
        
        try:
            # Use shutil for atomic file copy
            shutil.copy2(filepath, dest_path)
            with lock:
                print(f"Copied {filename} to {dest_dir}")
        except Exception as e:
            with lock:
                print(f"Error copying {filename}: {str(e)}")

def copy_elf_files(input_dir, max_threads):
    """Copy ELF files to architecture-specific subdirectories using multiple threads."""
    if not os.path.isdir(input_dir):
        print(f"Error: {input_dir} is not a valid directory")
        sys.exit(1)
    
    # Create subdirectories
    subdirs = create_subdirs(input_dir)
    
    # Collect all files
    files = [
        os.path.join(input_dir, filename)
        for filename in os.listdir(input_dir)
        if os.path.isfile(os.path.join(input_dir, filename))
    ]
    
    if not files:
        print("No files found in the directory")
        return
    
    # Use threading lock for safe printing
    print_lock = threading.Lock()
    
    # Process files using ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        executor.map(
            lambda f: process_file(f, subdirs, print_lock),
            files
        )

def main():
    parser = argparse.ArgumentParser(description="Copy ELF files to architecture-specific subdirectories")
    parser.add_argument("directory", help="Directory containing ELF files")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of threads to use (default: 1)")
    
    args = parser.parse_args()
    
    input_dir = args.directory
    max_threads = max(1, min(args.threads, os.cpu_count() or 1))  # Clamp threads to reasonable range
    
    print(f"Using {max_threads} threads to process files in {input_dir}")
    copy_elf_files(input_dir, max_threads)

# python3 filter_elf_based_on_architecture.py <directory_path>
if __name__ == "__main__":
    main()