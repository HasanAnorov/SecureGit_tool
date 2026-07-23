import json
import click
from pathlib import Path
from Crypto.PublicKey import ECC
from ..core.repo_operation import dec_patch_diff, dec_line_diff
from ..core.Git_command import get_git_diff_name
from git import Repo, GitCommandError, Actor
from ..core.crypto_tool import verify_commit, verify_publickey, ecies_decrypt_with_aesctr


@click.command()
@click.argument("plaintext_repo_path")
@click.argument("encrypted_repo_path")
@click.argument("owner_name")
@click.argument("user_name")
@click.option("--sym-key", "sym_key_path", default=None, help="Provide AES key directly")
@click.option("--private-key", "privkey_path", type=click.Path(exists=True), default=None, help="Path to your ECC private key to decrypt AES key")
@click.option("--sym-key-out", "key_out_path", type=click.Path(), default=None, help="Path to save decrypted AES key (default current directory)")
@click.argument("remote", default="origin")
@click.argument("branch", default="main")
def securegit_pull(plaintext_repo_path, encrypted_repo_path, owner_name, user_name, sym_key_path, privkey_path, key_out_path, remote, branch):
    """
    Pull latest commits from encrypted repo (can be multiple), decrypt each, and apply to plaintext repo.
    """
    encrypted_repo = Repo(encrypted_repo_path)
    plain_repo = Repo(plaintext_repo_path)

    enc_path = Path(encrypted_repo_path).resolve()
    plain_path = Path(plaintext_repo_path).resolve()

    if sym_key_path:
        with open(sym_key_path, "rb") as sym_file:
            sym_key = sym_file.read()
        print(f"[+] Loaded AES key from {sym_key_path} ({len(sym_key)} bytes)")
    elif privkey_path:
        with open(privkey_path, "rb") as priv_file:
            user_priv_key = priv_file.read()

        cipher_path = enc_path / "shareinfo" / f"{user_name}_keycipher.bin"
        if not cipher_path.exists():
            raise FileNotFoundError(f"[!] Cipher file not found: {cipher_path}")

        with open(cipher_path, "rb") as f2:
            enc_key = f2.read()

        sym_key = ecies_decrypt_with_aesctr(user_priv_key, enc_key)

        out_path = Path(key_out_path) if key_out_path else Path.cwd() / "symkey.bin"

        out_path.parent.mkdir(parents=True, exist_ok=True)

        with open(out_path, "wb") as f3:
            f3.write(sym_key)

    # 1. Fetch latest remote changes
    try:
        encrypted_repo.git.fetch(remote, branch)
        print(f"[+] Fetched latest changes from {remote}/{branch}")
    except GitCommandError as e:
        print(f"[!] Error fetching encrypted repo:\n{e}")
        return

    # 2. Get the list of new commits (not yet merged locally)
    new_commits = list(encrypted_repo.iter_commits(f'HEAD..{remote}/{branch}'))
    if not new_commits:
        print("[+] No new commits to pull.")
        return

    # Apply commits in chronological order
    new_commits.reverse()

    config_path = enc_path / "securegit_config.json"
    if not config_path.exists():
        raise FileNotFoundError(f"[!] Config not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    mode = config.get("mode")

    owner_key_path = enc_path / "shareinfo" / f"{owner_name}_sign_pub.der"
    if not owner_key_path.exists():
        raise FileNotFoundError(f"[!] Owner sign_pub not found: {owner_key_path}")
    with open(owner_key_path, "rb") as f1:
        owner_public_key = ECC.import_key(f1.read())

    for idx, commit in enumerate(new_commits, start=1):
        click.echo(f"[{idx}/{len(new_commits)}] Replaying encrypted commit {commit.hexsha[:12]} ...")

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

    print("[+] All decrypted changes staged in plaintext repo.")
    # 3. Fast-forward encrypted repo to remote
    try:
        encrypted_repo.git.merge(f'{remote}/{branch}', ff_only=True)
        print(f"[+] Encrypted repo updated to {remote}/{branch}")
    except GitCommandError as e:
        print(f"[!] Error merging encrypted repo:\n{e}")