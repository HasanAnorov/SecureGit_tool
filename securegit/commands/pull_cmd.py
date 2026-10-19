import json
import click
from pathlib import Path
from Crypto.PublicKey import ECC
from ..core.repo_operation import dec_patch_diff, dec_line_diff
from ..core.Git_command import get_git_diff_name
from git import Repo, GitCommandError, Actor
from ..core.crypto_tool import verify_commit, verify_publickey, ecies_decrypt_with_aesctr, split_commit_message
from ..core.branch_anchor_finder import resolve_in_plain
from ..core.access_branch import ACCESS_BRANCH

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

    # a pull replays commits and stages everything, so any uncommitted work
    # in the plaintext repo would be swept into someone else's commit
    if plain_repo.is_dirty(untracked_files=True):
        print("[!] Plaintext repo has uncommitted changes. Commit or stash them before pulling.")
        return

    # 1. Fetch latest remote changes
    try:
        # the access branch too, so the members and keys are always the newest
        encrypted_repo.git.fetch(remote, branch, ACCESS_BRANCH)
        print(f"[+] Fetched latest changes from {remote}/{branch} and {remote}/{ACCESS_BRANCH}")
    except GitCommandError as e:
        print(f"[!] Error fetching encrypted repo:\n{e}")
        return

    # 2. Commits on the remote branch that plain does not have yet,
    #    ordered so each parent comes before its children
    order = encrypted_repo.git.rev_list(f"{remote}/{branch}", "--not", branch,
                                        "--topo-order", "--reverse").split()
    new_commits = [encrypted_repo.commit(h) for h in order]
    if not new_commits:
        print("[+] No new commits to pull.")
        return

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

    # cipher commit hash -> the plaintext commit for it. The two branch tips
    # correspond: plain's branch was built from the cipher branch's current tip.
    plain_of = {encrypted_repo.commit(branch).hexsha: plain_repo.commit(branch)}

    # replay detached: the branch moves only once, after every commit succeeded
    plain_repo.git.checkout("--detach")

    for idx, commit in enumerate(new_commits, start=1):
        click.echo(f"[{idx}/{len(new_commits)}] Replaying encrypted commit {commit.hexsha[:12]} ...")

        # already built under another branch (e.g. by checkout)? reuse that copy
        try:
            plain_of[commit.hexsha] = resolve_in_plain(encrypted_repo, plain_repo, commit.hexsha)
            click.echo(f"    -> already in plaintext as {plain_of[commit.hexsha].hexsha[:12]}, reused.")
            continue
        except ValueError:
            pass

        if not verify_publickey(owner_public_key, commit):
            click.echo(f"[!] Creating plaintext commit failed")
            plain_repo.git.checkout("-f", branch)   # back to the untouched branch
            return

        username = commit.author.name
        public_file = commit.tree / "shareinfo" / f"{username}_sign_pub.der"
        public_key = public_file.data_stream.read()

        if not verify_commit(commit, public_key):
            click.echo(f"[!] Creating plaintext commit failed")
            plain_repo.git.checkout("-f", branch)   # back to the untouched branch
            return

        # the patch applies to this commit's first parent, so put that on disk first
        if commit.parents:
            parent = commit.parents[0].hexsha
            if parent not in plain_of:
                click.echo(f"[!] no plaintext commit known for parent {parent[:12]}; aborting")
                plain_repo.git.checkout("-f", branch)   # back to the untouched branch
                return
            target = plain_of[parent]
            if plain_repo.head.commit != target:
                plain_repo.git.checkout(target.hexsha)

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
            timestamp, msg, signature = split_commit_message(commit.message)
            author = Actor(commit.author.name, commit.author.email)
            committer = Actor(commit.committer.name, commit.committer.email)
            # Use same message; dates can be preserved via env vars, but we’ll keep it simple
            parents = [plain_of[p.hexsha] for p in commit.parents]
            new_commit = plain_repo.index.commit(
                msg,
                author=author,
                committer=committer,
                parent_commits=parents,
            )
            plain_of[commit.hexsha] = new_commit
            click.echo(f"    -> plaintext commit {new_commit.hexsha[:12]} created.")
        except Exception as e:
            click.echo(f"[!] Creating plaintext commit failed: {e}")
            plain_repo.git.checkout("-f", branch)   # back to the untouched branch
            return

    # the rewind left HEAD detached; move the branch to the new tip and return to it
    tip = plain_of[encrypted_repo.commit(f"{remote}/{branch}").hexsha]
    plain_repo.create_head(branch, tip.hexsha, force=True)
    plain_repo.git.checkout(branch)

    print("[+] All decrypted changes staged in plaintext repo.")
    # 3. Fast-forward encrypted repo to remote
    try:
        encrypted_repo.git.merge(f'{remote}/{branch}', ff_only=True)
        print(f"[+] Encrypted repo updated to {remote}/{branch}")
    except GitCommandError as e:
        print(f"[!] Error merging encrypted repo:\n{e}")