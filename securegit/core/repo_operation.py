from .file_operation import *
import os

def enc_patch_diff(plaintext_repo_path, encrypted_repo_path, result, key):
    repo_cipher = Path(encrypted_repo_path)
    repo_plain = Path(plaintext_repo_path)

    repo = Repo(plaintext_repo_path)

    for old_name, new_name in result['renamed_files']:
        move_and_rename_file(repo_cipher / old_name, repo_cipher / new_name)

    for del_name in result['deleted_files']:
        file_name = repo_cipher / del_name
        if os.path.exists(file_name):
            os.remove(file_name)

    for add_name in result['added_files']:
        if add_name != '.gitignore':
            os.makedirs(os.path.dirname(repo_cipher / add_name), exist_ok=True)
            process_one_whole_file(repo_plain / add_name, repo_cipher / add_name, key)

    for one_file in result['modified_files']:
        if one_file == '.gitignore':
            continue
        current_commit = repo.head.commit
        with open(repo_cipher / one_file, 'rb') as f1:
            original_cipher_bytes = f1.read()

        with open(repo_plain / one_file, 'rb') as f2:
            modified_text = f2.read()

        original_text = ''
        if current_commit:
            try:
                parent_content = current_commit.tree / one_file
                original_text = parent_content.data_stream.read()
            except KeyError:
                for old_name, new_name in result['renamed_files']:
                    if new_name == one_file:
                        parent_content = current_commit.tree / old_name
                        original_text = parent_content.data_stream.read()

        final_bytes = update_file_cipher_patch(original_cipher_bytes, original_text, modified_text, key)

        with open(repo_cipher / one_file, 'wb') as f4:
            f4.write(final_bytes + b'\n')


def enc_line_diff(plaintext_repo_path, encrypted_repo_path, result, key):

    # Git diff return return {
    #     "added_files": added_files,
    #     "added_files_content": added_files_content,
    #     "deleted_files": deleted_files,
    #     "renamed_files": renamed_files,
    #     "modified_files": modified_files,
    #     "deleted_lines": deleted_lines,
    #     "inserted_lines": inserted_lines,
    #     "inserted_content": inserted_content,
    # }
    # repo_cipher = Repo(encrypted_repo_path)


    repo_cipher = Path(encrypted_repo_path)
    repo_plain = Path(plaintext_repo_path)

    for old_name, new_name in result['renamed_files']:
        move_and_rename_file(repo_cipher / old_name, repo_cipher / new_name)

    for del_name in result['deleted_files']:
        file_name = repo_cipher / del_name
        if os.path.exists(file_name):
            os.remove(file_name)

    # note: The version of choice_commit should be displayed in the repo folder.

    for add_name in result['added_files']:
        if add_name == '.gitignore':
            continue
        os.makedirs(os.path.dirname(repo_cipher / add_name), exist_ok=True)
        process_file_by_line(repo_plain / add_name, repo_cipher / add_name, key)

    for one_file, one_del, one_add, one_add_lines in zip(result['modified_files'], result['deleted_lines']
                                                                ,result['inserted_lines'], result['inserted_content']):
        if one_file == '.gitignore':
            continue
        if one_add == [] and one_del == [] and one_add_lines == []:
            process_file_by_line(repo_plain / one_file, repo_cipher / one_file, key)
            continue

        with open(repo_cipher / one_file, 'rb') as f1:
            lines = f1.readlines()
            enc_bytes = b''.join(lines)

        cipher_lines = update_file_cipher_line(enc_bytes, one_del, one_add, one_add_lines, key)

        with open(repo_cipher / one_file, 'wb') as file:
            file.write(cipher_lines)

    remove_empty_dirs(repo_cipher, repo_plain)


def dec_patch_diff(plaintext_repo_path, diff, commit, symkey):
    plain_path = Path(plaintext_repo_path)

    for one_file in diff['added_files']:
        os.makedirs(os.path.dirname(plain_path / one_file), exist_ok=True)
        # print(plain_path / one_file)
        file_content = commit.tree / one_file
        text = file_content.data_stream.read()
        if one_file != '.gitignore':
            text = decrypt_aes(base64.b64decode(text), symkey)
        with open(plain_path / one_file, 'wb') as file:
            file.write(text)

    for one_file in diff['deleted_files']:
        file_name = plain_path / one_file
        if os.path.exists(file_name):
            os.remove(file_name)

    for old_name, new_name in diff['renamed_files']:
        move_and_rename_file(plain_path / old_name, plain_path / new_name)

    for one_file in diff['modified_files']:
        if one_file == '.gitignore':
            file_content = commit.tree / one_file
            text = file_content.data_stream.read()
            with open(plain_path / one_file, 'wb') as file:
                file.write(text)
            continue
        try:
            file_content = commit.tree / one_file
            text = file_content.data_stream.read()

            modified_line = text.strip().splitlines()[-1]

            decrypted_patch = decrypt_aes(base64.b64decode(modified_line), symkey).decode()

            patch = deserialize_patch(decrypted_patch)

            with open(plain_path / one_file, 'r') as f1:
                decrypted_text = f1.read()

            decrypted_text = apply_patch(decrypted_text, patch)

            decrypted_text = decrypted_text.encode()

            with open(plain_path / one_file, 'wb') as f2:
                f2.write(decrypted_text)

        except UnicodeDecodeError:
            file_content = commit.tree / one_file
            cipher = file_content.data_stream.read()
            decrypted_text = decrypt_aes(base64.b64decode(cipher))

            with open(plain_path / one_file, 'wb') as f2:
                f2.write(decrypted_text)
    return


def dec_line_diff(plaintext_repo_path, diff, commit, symkey):
    plain_path = Path(plaintext_repo_path)

    # for one_file in diff['added_files']:
    #     os.makedirs(os.path.dirname(plain_path / one_file), exist_ok=True)
    #     # print(plain_path / one_file)
    #     file_content = commit.tree / one_file
    #     text = file_content.data_stream.read()
    #     pt = decrypt_aes(base64.b64decode(text))
    #     with open(plain_path / one_file, 'wb') as file:
    #         file.write(pt)

    for one_file in diff['deleted_files']:
        file_name = plain_path / one_file
        if os.path.exists(file_name):
            os.remove(file_name)

    for old_name, new_name in diff['renamed_files']:
        move_and_rename_file(plain_path / old_name, plain_path / new_name)

    for one_file in diff['modified_files'] + diff['added_files']:
        os.makedirs(os.path.dirname(plain_path / one_file), exist_ok=True)
        if one_file == '.gitignore':
            file_content = commit.tree / one_file
            text = file_content.data_stream.read()
            with open(plain_path / one_file, 'wb') as file:
                file.write(text)
            continue
        try:
            file_content = commit.tree / one_file
            raw_bytes = file_content.data_stream.read()
            text = raw_bytes.decode('utf-8')  # decode to str
            lines = text.splitlines()

            line_num = len(lines)
            final_content = [None] * line_num
            for x in range(line_num):
                final_content[x] = decrypt_aes(base64.b64decode(lines[x]), symkey)
            final_plain = b''.join(final_content)

            with open(plain_path / one_file, 'wb') as f2:
                f2.write(final_plain)

        except UnicodeDecodeError:
            file_content = commit.tree / one_file
            cipher = file_content.data_stream.read()
            decrypted_text = decrypt_aes(base64.b64decode(cipher))
            with open(plain_path / one_file, 'wb') as f2:
                f2.write(decrypted_text)
    return