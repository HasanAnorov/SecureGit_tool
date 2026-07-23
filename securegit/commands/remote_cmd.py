import click
from git import Repo

@click.command(context_settings=dict(allow_interspersed_args=False))
@click.argument("encrypted_repo_path")
@click.argument("remote_args", nargs=-1)  # capture all extra args
def securegit_remote(encrypted_repo_path, remote_args):
    """
    securegit remote <plaintext_repo_path> <encrypted_repo_path> [remote_args...]
    Runs `git remote` with the same arguments in both plaintext and encrypted repos.
    Example:
        python -m securegit.cli remote myrepo myrepo_cipher add origin https://example.com/repo.git
    """

    # Open encrypted repo
    encrypted_repo = Repo(encrypted_repo_path)

    # Run git remote in encrypted repo
    result = encrypted_repo.git.remote(*remote_args)
    print(f"[+] Cipher repo: git remote {' '.join(remote_args)} executed.")

    print(result)
