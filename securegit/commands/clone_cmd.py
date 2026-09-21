import click
from pathlib import Path
from git import Repo, GitCommandError
from ..core.replay import load_crypto, build_branch

@click.command(name="clone", context_settings=dict(allow_interspersed_args=False))
@click.argument("remote_url")                  # e.g. https://github.com/user/encrypted_repo.git
@click.argument("encrypted_repo_path")         # local path to clone encrypted repo into
@click.argument("plaintext_repo_path")         # local path to build plaintext repo
@click.argument("owner_name")
@click.argument("sharee_name")
@click.argument("sharee_privkey")
@click.option("--sym_key_out", "symkey_path", type=click.Path(), help="Optional output path for symmetric key")
@click.option("--branch", "-b", default="main", help="Branch to clone/replay (default: main)")
def securegit_clone(remote_url, encrypted_repo_path, plaintext_repo_path, owner_name, sharee_name, sharee_privkey, symkey_path, branch):
    """
    securegit clone <remote_url> <encrypted_repo_path> <plaintext_repo_path> [-b branch]

    1) Clone the encrypted repo from remote
    2) Replay commits in chronological order:
       - For each commit, decrypt changed blobs and apply to plaintext working tree
       - Create a matching commit in the plaintext repo
    """

    if remote_url.startswith("git@"):
        parts = remote_url.split(":")[1].replace(".git", "").split("/")
    else:
        parts = remote_url.replace(".git", "").split("/")
    repo_owner = parts[-2] if len(parts) >= 2 else None
    repo_name = parts[-1] if len(parts) >= 2 else None

    enc_path = Path(encrypted_repo_path).resolve()
    plain_path = Path(plaintext_repo_path).resolve()

    # --- 1) Clone encrypted repo ---
    if enc_path.exists() and any(enc_path.iterdir()):
        click.echo(f"[!] Encrypted path '{enc_path}' is not empty. Aborting.")
        return
    try:
        click.echo(f"[+] Cloning encrypted repo from {remote_url} -> {enc_path} (branch: {branch}) ...")
        #new line edit - allowing securegit to have multiple branches
        enc_repo = Repo.clone_from(remote_url, enc_path, branch=branch)
    except GitCommandError as e:
        click.echo(f"[!] Clone failed: {e}")
        return

    # --- 2) Prepare plaintext repo directory ---
    if plain_path.exists():
        # optional: allow empty or prompt; here we require empty or non-existent
        if any(plain_path.iterdir()):
            click.echo(f"[!] Plaintext path '{plain_path}' is not empty. Aborting.")
            return
    else:
        plain_path.mkdir(parents=True, exist_ok=True)

    plain_repo = Repo.init(plain_path)
    click.echo(f"[+] Initialized plaintext repo at {plain_path}")

    try:
        # Ensure encrypted repo is on the requested branch
        if enc_repo.active_branch.name != branch:
            enc_repo.git.checkout(branch)

        crypto = load_crypto(enc_repo, owner_name, sharee_name, sharee_privkey)

        tip = build_branch(enc_repo, plain_repo, branch, branch, crypto)

        # clone is what saves the symmetric key for later use
        out_path = Path(symkey_path) if symkey_path else Path.cwd() / "symkey.bin"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(crypto.sym_key)

    except Exception as e:
        click.echo(f"[!] {e}")
        return

    if tip is None:
        click.echo("[*] No commits found to replay.")
        return

    click.echo("[✓] Replay finished. Plaintext repo is now restored with decrypted history.")