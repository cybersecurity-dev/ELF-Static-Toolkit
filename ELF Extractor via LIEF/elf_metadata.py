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