import sys
import re

def is_valid_version(version):
    # Check if version follows x.xx format
    return re.match(r'^\d\.\d{2}$', version) is not None

def is_valid_tid(tid):
    # Check if TID is 4 letters followed by 5 numbers
    return re.match(r'^[A-Za-z]{4}\d{5}$', tid) is not None

def add_header_to_elf(elf_filename, tid, version):
    # Validation checks
    if not is_valid_version(version):
        print("Error: Version must be in the format x.xx (e.g., 1.00)")
        return
    if not is_valid_tid(tid):
        print("Error: TID must be the first 4 letters followed by 5 numbers (e.g., ABCD12345)")
        return
    
    header_prefix = "etaHEN_PLUGIN"
    header = f"{header_prefix}\x00{tid}\x00{version}\x00"
    new_filename = (elf_filename.rsplit('.elf', 1)[0] if '.elf' in elf_filename else elf_filename) + ".plugin"

    try:
        with open(elf_filename, 'rb') as elf_file:
            elf_contents = elf_file.read()
            new_file_contents = header.encode() + elf_contents

        with open(new_filename, 'wb') as new_elf_file:
            new_elf_file.write(new_file_contents)

        verify_header(new_filename, len(header_prefix.encode()))

        formatted_header = header.replace('\x00', ' ').replace(header_prefix + ' ', '')
        print(f"Header added to {elf_filename} and saved as {new_filename}.")
        print(f"Plugin Info: {formatted_header}")
    except FileNotFoundError:
        print(f"Error: The file {elf_filename} was not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

def verify_header(file_name, prefix_length):
    with open(file_name, 'rb') as file:
        header = file.read(prefix_length)
        if header.startswith(b"etaHEN_PLUGIN"):
            print("Verification: Header correctly added.")
        else:
            print("Verification: Header not found.")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python script.py <ELF filename> <TID> <version>")
        sys.exit(1)

    elf_filename = sys.argv[1]
    tid = sys.argv[2]
    version = sys.argv[3]

    if is_valid_version(version) and is_valid_tid(tid):
        add_header_to_elf(elf_filename, tid, version)
    else:
        print("Invalid TID or version format.")