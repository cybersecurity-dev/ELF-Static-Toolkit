# ELF Internals


  
## Display the ELF file header
```bash
# -h --file-header  Display the ELF file header
readelf --file-header bin.elf
```

## Display the program headers
```bash
# -l --program-headers Display the program headers
readelf --program-headers bin.elf
```

## Display the sections' header
[extract_elf_section_headers_info()](https://github.com/cybersecurity-dev/ELF-Static-Toolkit/tree/main/ELF%20Extractor%20via%20LIEF/elf_sections_header.py#L7)
```bash
# -S --section-headers Display the sections' header
readelf --section-headers bin.elf
```

## Display the symbol table
```bash
# -s --syms              Display the symbol table
#    --symbols           An alias for --syms
readelf --symbols bin.elf
```

## Display histogram of bucket list lengths

```bash
# --histogram            Display histogram of bucket list lengths
readelf --symbols bin.elf
```

## Import Function names in ELF binary

In ELF they're called undefined symbols. You can view the list of undefined symbols by:
```bash
nm -D <file>|grep -w U
nm -C -D <file> | grep -w U | awk '{print $2}'
objdump -T <file>|grep "\*UND\*"
```

## Export Function names in ELF binary

To list the exported functions, you can use the following command:
```bash
nm -D <file> | grep -w U
nm -C -D <file> | grep -w T | awk '{print $3}'
objdump -T <file>|grep "\*UND\*"
```



```bash
Usage: readelf <option(s)> elf-file(s)
 Display information about the contents of ELF format files
 Options are:
  -a --all               Equivalent to: -h -l -S -s -r -d -V -A -I
  -h --file-header       Display the ELF file header
  -l --program-headers   Display the program headers
     --segments          An alias for --program-headers
  -S --section-headers   Display the sections' header
     --sections          An alias for --section-headers
  -g --section-groups    Display the section groups
  -t --section-details   Display the section details
  -e --headers           Equivalent to: -h -l -S
  -s --syms              Display the symbol table
     --symbols           An alias for --syms
  --dyn-syms             Display the dynamic symbol table
  -n --notes             Display the core notes (if present)
  -r --relocs            Display the relocations (if present)
  -u --unwind            Display the unwind info (if present)
  -d --dynamic           Display the dynamic section (if present)
  -V --version-info      Display the version sections (if present)
  -A --arch-specific     Display architecture specific information (if any)
  -c --archive-index     Display the symbol/file index in an archive
  -D --use-dynamic       Use the dynamic section info when displaying symbols
  -I --histogram         Display histogram of bucket list lengths
```


## Types of ELF Files
[get_elf_file_type()](https://github.com/cybersecurity-dev/ELF-Static-Toolkit/blob/main/ELF%20Extractor%20via%20LIEF/ELFxtractor_via_Lief.py#L)

In the context of ELF files, DYN, EXEC, REL, and CORE are four different types of ELF files.

* **EXEC** stands for "executable" file. This is a file that can be run directly by the operating system. When you double-click an executable file, the operating system loads it into memory and starts executing it.
* **DYN** stands for "dynamic" file. This is a file that is loaded into memory by another program. Dynamic files are typically used to store code or data that is shared between multiple programs.
* **REL** stands for "relocatable" file. This is a file that contains code and data that can be linked with other code and data to create an executable or dynamic file. Relocatable files are typically used to create libraries of code that can be reused by multiple programs.
* **CORE** stands for "core dump" file. This is a file that contains a snapshot of the memory of a program when it crashes. Core dump files are typically used to debug programs.

Here is a table that summarizes the key differences between these four types of ELF files:


| Feature                                                      | EXEC | DYN | REL | CORE |
|--------------------------------------------------------------|------|-----|-----|------|
| Can be run directly by the operating system                  | Yes  | No  | No  | No   |
| Typically used to store code or data that is shared between | No   | Yes | No  | No   |
| multiple programs                                          |      |     |     |      |
| Can be linked with other code and data to create an          | No   | No  | Yes | No   |
| executable or dynamic file                                  |      |     |     |      |
| Contains a snapshot of the memory of a program when it       | No   | No  | No  | Yes  |
| crashes                                                      |      |     |     |      |



## Types of Segments

* **PHDR**: This segment contains the program headers themselves, which are like a table of contents for the executable file.
* **INTERP**: This segment specifies the interpreter that should be used to execute the program.
* **LOAD**: This segment contains code or data that needs to be loaded into memory to run the program.
* **DYNAMIC**: This segment contains information needed for dynamic linking, which is a way to link libraries of code at runtime.
* **NOTE**: This segment contains additional information that might be useful for debugging or other tools.
* **GNU_EH_FRAME**: This segment contains information about exception handling, which is a way for the program to gracefully deal with errors.
* **GNU_STACK**: This segment indicates settings for the stack, which is a region of memory used for function calls and local variables.


