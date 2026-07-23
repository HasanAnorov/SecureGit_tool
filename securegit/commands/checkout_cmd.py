import click
from git import Repo, GitCommandError

@click.command(name="checkout", context_settings=dict(ignore_unknown_options=True))
@click.argument("plaintext_repo_path")
@click.argument("encrypted_repo_path")
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def securegit_checkout(plaintext_repo_path, encrypted_repo_path, args):
    """
    Secure version of 'git checkout'.
    Behaves like 'git checkout', but runs on both plaintext and encrypted repos.
    """

    plain_repo = Repo(plaintext_repo_path)
    enc_repo = Repo(encrypted_repo_path)

    args_str = " ".join(args)
    click.echo(f"[*] Running checkout with args: {args_str}")

    try:
        plain_repo.git.checkout(*args)
        click.echo("[✓] Plaintext repo checkout successful")
    except GitCommandError as e:
        click.echo(f"[!] Plaintext repo checkout failed: {e}")
        return

    try:
        enc_repo.git.checkout(*args)
        click.echo("[✓] Encrypted repo checkout successful")
    except GitCommandError as e:
        click.echo(f"[!] Encrypted repo checkout failed: {e}")
        return
