import click
from git import Repo, GitCommandError
from ..core.access_branch import ACCESS_BRANCH

def _remote_branches(enc_repo, remote):
    """Code branch name -> commit hash, as the encrypted repo knows the server."""
    return {ref.remote_head: ref.commit.hexsha
            for ref in enc_repo.remote(remote).refs if ref.remote_head not in ("HEAD", ACCESS_BRANCH)}

def _access_tip(enc_repo, remote):
    """Commit hash of the server's access branch as the encrypted repo knows it ('' if none)."""
    try:
        return enc_repo.commit(f"{remote}/{ACCESS_BRANCH}").hexsha
    except Exception:
        return ""

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

    try:
        before = _remote_branches(enc_repo, remote)
    except ValueError:
        click.echo(f"[!] No remote named '{remote}' in the encrypted repo.")
        return
    access_before = _access_tip(enc_repo, remote)

    try:
        enc_repo.git.fetch(remote)
    except GitCommandError as e:
        click.echo(f"[!] Fetch failed: {e}")
        return
    after = _remote_branches(enc_repo, remote)

    built = [h.name for h in plain_repo.heads]
    enc_local = [h.name for h in enc_repo.heads]
    reported = False
    if _access_tip(enc_repo, remote) != access_before:
        click.echo("[+] Access branch updated (members or keys changed).")
        reported = True
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