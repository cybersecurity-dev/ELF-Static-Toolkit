import hashlib
import lief
import os
import math

def calculate_sha256(fpath):
    sha256_hash = hashlib.sha256()
    with open(fpath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

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

def get_elf_file_type(fpath):
    """Gets the ELF file type of an ELF file."""
    binary = lief.parse(fpath)
    if binary is None:
        raise Exception(f"Failed to parse:{fpath}")
        return None
    return binary.header.file_type.name

# checks if the current user has execute permissions 
def has_execute_permissions (fpath):
    return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

def is_elf_file(fpath) -> bool:
    """
    Checks ELF file by inspecting its magic bytes.
    """
    with open(fpath, 'rb') as f:
        magic_bytes = f.read(4)
        return magic_bytes == b'\x7fELF'

def detect_architecture(fpath) -> str:
    binary = lief.parse(fpath)
    if binary is None:
        print(f"File is not Binary:{fpath}\n")
        raise Exception("Failed to parse the binary.")

    try:
        machine_type = binary.header.machine_type
    except ValueError as e: #ValueError: 255 is not a valid ARCH.
        print(f"section type error:{fpath}")
        ARCH_type_value = int(str(e).split()[0])
        return f"Unknown ELF architecture ({ARCH_type_value})"

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

def extract_elf_file_notes_info(elf, fpath) -> dict:
    owner = None
    build_id = None
    abi_version = None
    try:
        owner, build_id = get_build_id(elf)
        owner, abi_version = get_abi_version(elf)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        print(f"File:{fpath}")
    return {"owner" : owner, "build_id" : build_id, "abi_version" : abi_version}
