from git import Repo
import click
from ..core.Git_command import get_git_diff_name, Get_git_diff
from ..core.repo_operation import enc_patch_diff, enc_line_diff
from pathlib import Path
import json

CONFIG_FILENAME = "securegit_config.json"

@click.command()
@click.option("--char", "mode", flag_value="char", help="Encrypt in char mode")
@click.option("--line", "mode", flag_value="line", help="Encrypt in line mode")
@click.argument("plaintext_repo_path", required=True)
@click.argument("encrypted_repo_path", required=True)
@click.argument("key_path", required=True)
def securegit_add(mode, plaintext_repo_path, encrypted_repo_path, key_path):
    """Secure version of git add that also updates the encrypted repo."""
    config_path = Path(encrypted_repo_path) / CONFIG_FILENAME

    # --- Load or initialize config ---
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        mode = config.get("mode")
        if mode not in ("char", "line"):
            raise click.UsageError("Invalid config mode. Please delete config and re-run with --char or --line.")
        print(f"[=] Loaded encryption mode '{mode}' from {config_path}")
    else:
        # First time: require user to pass --char or --line
        if mode not in ("char", "line"):
            raise click.UsageError("Please specify either --char or --line on first use.")
        config = {"mode": mode}
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        print(f"[+] Saved encryption mode '{mode}' into {config_path}")


    # run `git add . ' in plain repo
    plaintext_repo = Repo(plaintext_repo_path)
    plaintext_repo.git.add("-A")
    print("[+] Added all changes to plaintext repo index.")

    with open(key_path, "rb") as sym_file:
        aes_private_key = sym_file.read()
    print(f"[+] Loaded AES key from {key_path} ({len(aes_private_key)} bytes)")

    # enc modified files
    if mode == "char":
        diff_info = get_git_diff_name(plaintext_repo)
        print(f"[+] Diff info: {diff_info}")

        enc_patch_diff(plaintext_repo_path, encrypted_repo_path, diff_info, aes_private_key)
    else:

        diff_info = Get_git_diff(plaintext_repo)
        print(f"[+] Diff info: {diff_info}")
        enc_line_diff(plaintext_repo_path, encrypted_repo_path, diff_info, aes_private_key)

    print("[+] Encrypted files updated in encrypted repo working dir.")


    encrypted_repo = Repo(encrypted_repo_path)
    encrypted_repo.git.add("-A")
    print("[+] Added all changes to encrypted repo index.")
