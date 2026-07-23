import json
import click
from pathlib import Path
from Crypto.PublicKey import ECC
from git import Repo, GitCommandError, Actor
from ..core.Git_command import get_git_diff_name
from ..core.repo_operation import dec_patch_diff, dec_line_diff
from ..core.crypto_tool import verify_commit, verify_publickey, ecies_decrypt_with_aesctr

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
        enc_repo = Repo.clone_from(remote_url, enc_path, branch=branch, single_branch=True)
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
        commits = list(enc_repo.iter_commits(branch))
        if not commits:
            click.echo("[*] No commits found to replay.")
            return
        commits.reverse()  # chronological order
        click.echo(f"[+] Found {len(commits)} commits to replay.")
    except Exception as e:
        click.echo(f"[!] Failed to enumerate commits: {e}")
        return

    owner_key_path = enc_path / "shareinfo" / f"{owner_name}_sign_pub.der"
    if not owner_key_path.exists():
        raise FileNotFoundError(f"[!] Owner sign_pub not found: {owner_key_path}")
    with open(owner_key_path, "rb") as f1:
        owner_public_key = ECC.import_key(f1.read())

    with open(sharee_privkey, "rb") as priv_file:
        user_priv_key = priv_file.read()

    cipher_path = enc_path / "shareinfo" / f"{sharee_name}_keycipher.bin"
    if not cipher_path.exists():
        raise FileNotFoundError(f"[!] Cipher file not found: {cipher_path}")

    with open(cipher_path, "rb") as f2:
        enc_key = f2.read()

    sym_key = ecies_decrypt_with_aesctr(user_priv_key, enc_key)

    out_path = Path(symkey_path) if symkey_path else Path.cwd() / "symkey.bin"

    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "wb") as f3:
        f3.write(sym_key)

    config_path = enc_path / "securegit_config.json"
    if not config_path.exists():
        raise FileNotFoundError(f"[!] Config not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    mode = config.get("mode")

    encrypted_repo = Repo(encrypted_repo_path)

    # --- 4) Replay commits one by one ---
    for idx, commit in enumerate(commits, start=1):
        click.echo(f"[{idx}/{len(commits)}] Replaying encrypted commit {commit.hexsha[:12]} ...")
        if not verify_publickey(owner_public_key, commit):
            click.echo(f"[!] Creating plaintext commit failed")
            return

        username = commit.author.name
        public_file = commit.tree / "shareinfo" / f"{username}_sign_pub.der"
        public_key = public_file.data_stream.read()

        if not verify_commit(commit, public_key):
            click.echo(f"[!] Creating plaintext commit failed")
            return

        if mode == 'char':
            diff_info = get_git_diff_name(encrypted_repo, commit.hexsha)
            print(diff_info)
            dec_patch_diff(plaintext_repo_path, diff_info, commit, sym_key)
        else:
            diff_info = get_git_diff_name(encrypted_repo, commit.hexsha)
            print(diff_info)
            dec_line_diff(plaintext_repo_path, diff_info, commit, sym_key)

        plain_repo.git.add("-A")

        # Commit in plaintext repo mirroring original message/author
        try:
            separated_msg = commit.message.split('|')
            author = Actor(commit.author.name, commit.author.email)
            committer = Actor(commit.committer.name, commit.committer.email)
            # Use same message; dates can be preserved via env vars, but we’ll keep it simple
            new_commit = plain_repo.index.commit(
                separated_msg[1],
                author=author,
                committer=committer,
            )
            click.echo(f"    -> plaintext commit {new_commit.hexsha[:12]} created.")
        except Exception as e:
            click.echo(f"[!] Creating plaintext commit failed: {e}")
            return

    click.echo("[✓] Replay finished. Plaintext repo is now restored with decrypted history.")


