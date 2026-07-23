import click
from git import Repo, GitCommandError
from pathlib import Path
import json

CONFIG_FILENAME = "securegit_config.json"

@click.command(name="merge", context_settings=dict(ignore_unknown_options=True))
@click.argument("plain_repo_path", required=True)
@click.argument("encrypted_repo_path", required=True)
@click.argument("branch_name_a", required=True)
@click.argument("branch_name_b", required=True)
def securegit_merge(plain_repo_path, encrypted_repo_path, branch_name_a, branch_name_b):
    """
    Secure version of 'git merge' with encryption support.
    """

    config_path = Path(encrypted_repo_path) / CONFIG_FILENAME

    mode = ''

    # --- Load or initialize config ---
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        mode = config.get("mode")
        if mode not in ("char", "line"):
            raise click.UsageError("Invalid config mode. Please delete config and re-run with --char or --line.")
        print(f"[=] Loaded encryption mode '{mode}' from {config_path}")

    plain_repo = Repo(plain_repo_path)
    enc_repo = Repo(encrypted_repo_path)

    try:
        plain_repo.git.merge(branch_name_b, ff_only=True)
        print(f"[✓] plain repo fast-forward merge to '{branch_name_b}' completed successfully.")
        enc_repo.git.merge(branch_name_b, ff_only=True)
        print(f"[✓] encrypted repo fast-forward merge to '{branch_name_b}' completed successfully.")
        return
    except GitCommandError as e:
        print(f"[!] Fast-forward merge not possible")
        # print("[*] Repository state remains unchanged.")

    base = plain_repo.git.merge_base(branch_name_a, branch_name_b)
    files_a = set(plain_repo.git.diff(base, branch_name_a, name_only=True).splitlines())
    files_b = set(plain_repo.git.diff(base, branch_name_b, name_only=True).splitlines())

    overlap = files_a & files_b
    if not overlap:
        print("[✓] No overlapping files. Safe to merge directly.")
        try:
            plain_repo.git.merge(branch_name_b, "--no-commit", "--no-ff")
            print(f"[✓] Plain repo: Branch {branch_name_b} merged into {branch_name_a} successfully. Please run securegit commit")
            enc_repo.git.merge(branch_name_b, "--no-commit", "--no-ff")
            print(f"[✓] encrypted repo: Branch {branch_name_b} merged into {branch_name_a} successfully. Please run securegit commit")
            return
        except GitCommandError as e:
            print(f"[!] Merge failed: {e}")
            return

    if mode == 'line':
        try:
            plain_repo.git.merge(branch_name_b, "--no-commit", "--no-ff")
            enc_repo.git.merge(branch_name_b, "--no-commit", "--no-ff")
            click.echo("[+] Merge successful. Please run securegit commit.")
        except GitCommandError as e:
            enc_repo.git.merge(branch_name_b, "--no-commit", "--no-ff", "-X", "ours")
            click.echo(f"[!] Merge failed: {e}")
            click.echo(
                "[!] Merge conflict detected in line mode. Please resolve manually, then run securegit add + commit.")
            # plain_repo.git.merge("--abort")
            return

    if mode == 'char':
        try:
            plain_repo.git.merge(branch_name_b, "--no-commit", "--no-ff")
        except GitCommandError as e:
            enc_repo.git.merge(branch_name_b, "--no-commit", "--no-ff", "-X", "ours")
            click.echo(f"[!] Merge failed: {e}")
            click.echo(
                "[!] Merge conflict detected in char mode. Please resolve manually, then run securegit add + commit.")
            # plain_repo.git.merge("--abort")
            return

        enc_repo.git.merge(branch_name_b, "--no-commit", "--no-ff", "-X", "ours")
        click.echo(
            "[!] No conflict detected in char mode. Please run securegit add + commit.")
        # plain_repo.git.merge("--abort")
        return