import os
import sys

from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

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

def copy_elf_files(input_dir):
    """Copy ELF files to architecture-specific subdirectories."""
    if not os.path.isdir(input_dir):
        print(f"Error: {input_dir} is not a valid directory")
        sys.exit(1)
    
    # Create subdirectories
    subdirs = create_subdirs(input_dir)
    
    # Process files
    for filename in os.listdir(input_dir):
        filepath = os.path.join(input_dir, filename)
        
        if os.path.isfile(filepath):
            arch = get_elf_architecture(filepath)
            if arch:
                dest_dir = subdirs[arch]
                dest_path = os.path.join(dest_dir, filename)
                
                try:
                    with open(filepath, 'rb') as src, open(dest_path, 'wb') as dst:
                        dst.write(src.read())
                    print(f"Copied {filename} to {dest_dir}")
                except Exception as e:
                    print(f"Error copying {filename}: {str(e)}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 filter_elf_based_on_architecture.py <directory_path>")
        sys.exit(1)
    
    input_dir = sys.argv[1]
    copy_elf_files(input_dir)

if __name__ == "__main__":
    main()