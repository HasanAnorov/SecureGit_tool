import time
from .crypto_tool import *
from pathlib import Path
from .Char_diff_tool import *

def move_and_rename_file(source_path, target_path, overwrite=False):
    """
    Move and rename the file (or create the destination directory if it doesn't exist).

    :param source_path: The full path to the source file
    :param target_path: The full path to the object file
    :param overwrite: Whether to overwrite the object file if it already exists (Default False)
    """
    source_path = Path(source_path)
    target_path = Path(target_path)

    if not source_path.exists():
        raise FileNotFoundError(f"source path does not exist: {source_path}")

    # Make sure the destination directory exists
    target_dir = target_path.parent
    target_dir.mkdir(parents=True, exist_ok=True)

    # if the file already exists
    if target_path.exists():
        if overwrite:
            target_path.unlink()  # delete
        else:
            raise FileExistsError(f"source path already exists: {target_path}")

    # Perform file movement (with filename changes supported)
    source_path.rename(target_path)
    #print(f"The file has been moved and renamed: {source_path} -> {target_path}")

def remove_empty_dirs(base_dir, reference_dir):
    """
    Removes the empty folder in base_dir or if the path does not exist in reference_dir.

    :param base_dir: Folders to clean up
    :param reference_dir: Reference folder
    """
    base_dir = Path(base_dir).resolve()
    reference_dir = Path(reference_dir).resolve()

    # Iterate over all subdirectories of base_dir
    for folder in sorted(base_dir.rglob("*"), key=lambda p: -len(p.parts)):
        if folder.is_dir() and not any(folder.iterdir()):  # Folder directory is empty
            relative_path = folder.relative_to(base_dir)  # Calculate relative paths
            reference_path = reference_dir / relative_path  # Compute the corresponding path in Reference folder

            if not reference_path.exists():
                try:
                    folder.rmdir()
                    #print(f"Deleted empty folder: {folder}")
                except Exception as e:
                    print(f"Failed to delete {folder}: {e}")

def process_file_by_line(file_path, target_file_path, key):
    # If the file can be Unicode decoded follow the line encryption otherwise encrypt the entire file
    try:
        with open(file_path, 'r', encoding='utf-8') as f1:
            final_content = b''
            for line in f1.readlines():
                # print(line)
                final_content += base64.b64encode(encrypt_aes(line.encode(), key)) + b'\n'
            with open(target_file_path, 'wb') as f2:
                f2.write(final_content)
        #print(f'[* copy_project_and_encrypt_files log] encrypt one file {file_path} to {target_file_path} by lines')
    except UnicodeDecodeError:
        with open(file_path, 'rb') as f1:
            content = f1.read()
        cipher = base64.b64encode(encrypt_aes(content, key))
        with open(target_file_path, 'wb') as f2:
            f2.write(cipher)
        #print(f'[* copy_project_and_encrypt_files log] encrypt one file {file_path} to {target_file_path} by whole')
    end = time.perf_counter()
    return

def process_one_whole_file(file_path, target_file_path, key):
    with open(file_path, 'rb') as f1:
        content = f1.read()
    cipher = base64.b64encode(encrypt_aes(content, key))
    with open(target_file_path, 'wb') as f2:
        f2.write(cipher + b'\n')
    return


def update_file_cipher_line(enc_byte, lines_to_delete, lines_to_insert, line_context, key):
    lines_to_delete_set = set(lines_to_delete)

    enc_byte = enc_byte.splitlines()

    lines = [line for i, line in enumerate(enc_byte, start=1) if i not in lines_to_delete_set]

    final_size = len(lines) + len(lines_to_insert)
    updated_lines = [None] * final_size

    plain_len = 0
    current_insert_index = 0  # Index of the current insertion point
    current_updated_index = 0

    cipher_delta_len = 0

    for current_line_no, line in enumerate(lines):
        # insert new lines
        while (current_insert_index < len(lines_to_insert) and
               lines_to_insert[current_insert_index] == current_updated_index + 1):
            content = line_context[current_insert_index]
            plain_len = plain_len + len(content.encode())
            # if len(content.encode()) != 500:
            #     print(f"line index: {current_updated_index + 1}, line len: {len(content.encode())}")

            one_line_enc_byte = base64.b64encode(encrypt_aes(content.encode() + b'\n', key))
            cipher_delta_len = cipher_delta_len + len(one_line_enc_byte)

            #one_line_enc_byte = content.encode()
            updated_lines[current_updated_index] = one_line_enc_byte
            current_updated_index += 1
            current_insert_index += 1

        # insert the current line
        updated_lines[current_updated_index] = line
        current_updated_index += 1

        # Insert line numbers beyond the end of the file
    while current_insert_index < len(lines_to_insert):
        content = line_context[current_insert_index]
        start_enc1 = time.perf_counter()
        one_line_enc_byte = base64.b64encode(encrypt_aes(content.encode() + b'\n', key))
        cipher_delta_len = cipher_delta_len + len(one_line_enc_byte)
        plain_len = plain_len + len(content.encode())
        updated_lines[current_updated_index] = one_line_enc_byte
        current_updated_index += 1
        current_insert_index += 1
    return b'\n'.join(updated_lines) + b'\n'


def update_file_cipher_patch(enc_byte, parent_data_byte, current_data_byte, key):
    try:
        parent_data_str = parent_data_byte.decode('utf-8')
        #print(parent_data_str)
        current_data_str = current_data_byte.decode('utf-8')
        #print(current_data_str)
        patch = create_patch(parent_data_str, current_data_str)
        serialized_patch = serialize_patch(patch)
        #print(serialized_patch)
        enc_serialized_patch = base64.b64encode(encrypt_aes(serialized_patch.encode(), key))
        final_byte = enc_byte
        final_byte += enc_serialized_patch
    except UnicodeDecodeError:
        enc_byte = encrypt_aes(current_data_byte, key)
        final_byte = base64.b64encode(enc_byte)
    return final_byte