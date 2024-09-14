import sys
import os
import os.path, time
import lief
import pandas as pd

# Initialize a dictionary to hold the ELF data
elf_data = {}

# Extract ELF header information
def extract_elf_header_info(elf):
    header_info = {
        "ELF Class": str(elf.header.identity_class),
        "ELF Data": str(elf.header.identity_data),
        "Machine Type": str(elf.header.machine_type),
        "Entry Point": hex(elf.header.entrypoint),
        "Number of Sections": len(elf.sections),
        "Number of Segments": len(elf.segments),
        "Section Header Offset": elf.header.section_header_offset,
        "Program Header Offset": elf.header.program_header_offset,
        "File Type": str(elf.header.file_type),
    }
    
    # Add header information to the ELF data dictionary
    elf_data.update(header_info)

def main(df_csv_path, df_pkl_path):
    # Load the ELF file
    elf_file_path = "./elf/SlackSetup.elf"  # Replace with your ELF file path
    elf = lief.parse(elf_file_path)

    # Call the extraction functions
    extract_elf_header_info(elf)
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