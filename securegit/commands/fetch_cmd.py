import click
from git import Repo, GitCommandError


def _remote_branches(enc_repo, remote):
    """Branch name -> commit hash, as the encrypted repo knows the server."""
    return {ref.remote_head: ref.commit.hexsha
            for ref in enc_repo.remote(remote).refs if ref.remote_head != "HEAD"}


@click.command(name="fetch")
@click.argument("plaintext_repo_path")
@click.argument("encrypted_repo_path")
@click.argument("remote", default="origin")
def securegit_fetch(plaintext_repo_path, encrypted_repo_path, remote):
    """
    Download new branches and commits into the encrypted repo.
    The plaintext repo is not touched; build a new branch with 'securegit checkout'.
    """
    plain_repo = Repo(plaintext_repo_path)
    enc_repo = Repo(encrypted_repo_path)

    before = _remote_branches(enc_repo, remote)
    try:
        enc_repo.git.fetch(remote)
    except GitCommandError as e:
        click.echo(f"[!] Fetch failed: {e}")
        return
    after = _remote_branches(enc_repo, remote)

    built = [h.name for h in plain_repo.heads]
    enc_local = [h.name for h in enc_repo.heads]
    reported = False
    for name in sorted(after):
        if name not in before and name not in built:
            click.echo(f"[+] New branch '{name}'. Build it with: "
                       f"securegit checkout {plaintext_repo_path} {encrypted_repo_path} {name}")
            reported = True
        elif name in built and name in enc_local:
            new = int(enc_repo.git.rev_list("--count", f"{name}..{remote}/{name}"))
            if new:
                click.echo(f"[+] '{name}' has {new} new commit(s). Update it with: securegit pull")
                reported = True
    if not reported:
        click.echo("[+] Already up to date.")