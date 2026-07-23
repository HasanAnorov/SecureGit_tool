import sys
import click
from git import Repo

@click.command(context_settings=dict(allow_interspersed_args=False))
@click.argument("plaintext_repo_path")
@click.argument("encrypted_repo_path")
@click.argument("branch_args", nargs=-1)  # capture all extra args (including -M)
def securegit_branch(plaintext_repo_path, encrypted_repo_path, branch_args):
    """
    securegit branch <plaintext_repo_path> <encrypted_repo_path> [git branch args...]
    Execute `git branch` in both plaintext and encrypted repositories.
    """

    # Open plaintext and encrypted repositories
    try:
        plaintext_repo = Repo(plaintext_repo_path)
        encrypted_repo = Repo(encrypted_repo_path)
    except Exception as e:
        print(f"[!] Failed to open repositories: {e}")
        sys.exit(1)

    # Execute in plaintext repository
    try:
        result_plain = plaintext_repo.git.branch(*branch_args)
        if result_plain.strip():
            print("[Plaintext repository branch info]:")
            print(result_plain)
    except Exception as e:
        print(f"[!] Error executing branch in plaintext repository: {e}")

    # Execute in encrypted repository
    try:
        result_cipher = encrypted_repo.git.branch(*branch_args)
        if result_cipher.strip():
            print("[Encrypted repository branch info]:")
            print(result_cipher)
    except Exception as e:
        print(f"[!] Error executing branch in encrypted repository: {e}")
