import os
import click
from git import Repo

@click.command()
@click.argument("name", required=True)
@click.option("--key-path", default="symkey.bin", help="Path to save the generated key file (default: ./securegit.key)")
def securegit_init(name, key_path):
    """
    Initialize a SecureGit repository with plaintext and encrypted repos,
    and generate a random 32-byte key file.

    NAME: Repository name (plaintext repo will be NAME, encrypted repo will be NAME_cipher)
    """
    plaintext_path = os.path.abspath(name)
    encrypted_path = os.path.abspath(f"{name}_cipher")

    if os.path.exists(plaintext_path):
        click.echo(f"[!] Directory already exists: {plaintext_path}")
        return
    if os.path.exists(encrypted_path):
        click.echo(f"[!] Directory already exists: {encrypted_path}")
        return

    # --- Initialize plaintext repo ---
    os.makedirs(plaintext_path)
    Repo.init(plaintext_path)
    click.echo(f"[+] Initialized plaintext repository at {plaintext_path}")

    # --- Initialize encrypted repo ---
    os.makedirs(encrypted_path)
    Repo.init(encrypted_path)
    click.echo(f"[+] Initialized encrypted repository at {encrypted_path}")

    # --- Generate random 32-byte key ---
    key_bytes = os.urandom(32)
    key_path = os.path.abspath(key_path)

    # Ensure directory exists
    os.makedirs(os.path.dirname(key_path), exist_ok=True)

    with open(key_path, "wb") as f:
        f.write(key_bytes)

    click.echo(f"[+] Generated random 32-byte key at {key_path}")

    click.echo("[*] SecureGit initialized successfully.")
    click.echo(f"    Plaintext repo: {plaintext_path}")
    click.echo(f"    Encrypted repo: {encrypted_path}")
    click.echo(f"    Key file: {key_path}")
