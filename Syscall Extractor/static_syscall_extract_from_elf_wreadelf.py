import subprocess
import sys

SYSCALLS = {'read', 'write', 'open', 'close', 'fork', 'execve', 'exit'}  # POC

def find_system_calls_wreadelf(binary_path):
    try:
        # Run readelf to get dynamic symbols
        result = subprocess.run(['readelf', '--dyn-syms', binary_path], capture_output=True, text=True, check=True)
        output = result.stdout

        found_syscalls = set()
        for line in output.splitlines():
            for syscall in SYSCALLS:
                if syscall in line:
                    found_syscalls.add(syscall)

        if found_syscalls:
            print("System calls found:")
            for syscall in sorted(found_syscalls):
                print(f" - {syscall}")
        else:
            print("No recognized system calls found.")

    except subprocess.CalledProcessError as e:
        print(f"Error running readelf: {e}")
    except FileNotFoundError:
        print(f"Error: File '{binary_path}' not found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 static_syscall_extract_from_elf_wreadelf.py <path_to_binary>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    find_system_calls_wreadelf(binary_path)