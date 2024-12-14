import sys
import os
import os.path, time
import lief
import pandas as pd

# Initialize a dictionary to hold the ELF data
elf_data = {}

# Extract ELF header information
def extract_elf_header_info(elf_file):
    # Extract ELF header information
    eheader = elf_file.header
    header_info = {
        "File Type": str(eheader.file_type),
        "Machine Type": str(eheader.machine_type),
        "Entry Point": hex(eheader.entrypoint),
        "Program Header Offset": eheader.program_header_offset,
        "Section Header Offset": eheader.section_header_offset,
        "Section Header Offset": eheader.section_header_offset,
        "Program Header Offset": eheader.program_header_offset,
        "Processor Flags": eheader.processor_flag,
        "Header Size": eheader.header_size,
        "Program Header Size": eheader.program_header_size,
        "Number of Program Headers": eheader.numberof_segments,
        "Section Header Size": eheader.section_header_size,
        "Number of Section Headers": eheader.numberof_sections,
        "Section Header String Table Index": eheader.section_name_table_idx,
        "ELF Class": str(eheader.identity_class),
        "ELF Data": str(eheader.identity_data)
    }
    
    # Add header information to the ELF data dictionary
    elf_data.update(header_info)

def extract_elf_section_info(elf_file):
    # Extract section information
    esections = elf_file.sections
    sections_info = {
        "Number of Sections": len(elf_file.sections)
    }
    for section in esections:
        sections_info[f"{section.name}_type"] = section.type
        sections_info[f"{section.name}_flags"] = section.flags
        sections_info[f"{section.name}_virtual_address"] = hex(section.virtual_address)
        sections_info[f"{section.name}_offset"] = section.offset
        sections_info[f"{section.name}_size"] = section.size
        sections_info[f"{section.name}_entropy"] = section.entropy

    # Add section information to the ELF data dictionary
    elf_data.update(sections_info)

# Extract ELF dynamic entries and symbols (equivalent to imports/exports)
def extract_elf_dynamic_info(elf):
    # Dynamic entries (imports)
    dynamic_info = []
    for dynamic_entry in elf.dynamic_entries:
        dynamic_info.append(f"Tag: {dynamic_entry.tag}, Value: {dynamic_entry.value}")
    
    elf_data["Dynamic Entries"] = dynamic_info if dynamic_info else "None"
    
    # Exported functions (symbols)
    exported_symbols = []
    for symbol in elf.symbols:
        if symbol.exported:
            exported_symbols.append(f"Symbol: {symbol.name}, Value: {symbol.value}")
    
    elf_data["Exported Symbols"] = exported_symbols if exported_symbols else "None"
    
    # Imported functions (symbols)
    imported_symbols = []
    for symbol in elf.imported_symbols:
        imported_symbols.append(f"Symbol: {symbol.name}, Value: {symbol.value}")
    
    elf_data["Imported Symbols"] = imported_symbols if imported_symbols else "None"


def main(df_csv_path, df_pkl_path):
    # Load the ELF file
    elf_file_path = "./elf/SlackSetup.elf"  # Replace with your ELF file path
    elf = lief.parse(elf_file_path)

    # Call the extraction functions
    extract_elf_header_info(elf)
    extract_elf_section_info(elf)
    #extract_elf_dynamic_info(elf)

    # Convert the ELF data dictionary into a DataFrame
    df = pd.DataFrame([elf_data])

    # Save DataFrame as CSV
    df.to_csv(df_csv_path, index=False)

    # Save DataFrame as pickle (.pkl)
    df.to_pickle(df_pkl_path)

if __name__ == "__main__":
  print("[" + __file__ + "]'s last modified: %s" % time.ctime(os.path.getmtime(__file__)))
  # Save the DataFrame to a CSV file and pickle file
  df_csv_path = "elf_file_information_by_column.csv"
  df_pkl_path = "elf_file_information_by_column.pkl"
  main(df_csv_path, df_pkl_path)
  print(f"ELF information saved to {df_csv_path} and {df_pkl_path}")





