import click
from pathlib import Path
from ..core.repo_operation import dec_patch_diff, dec_line_diff
from ..core.Git_command import get_git_diff_name
from git import Repo, GitCommandError, Actor
from ..core.crypto_tool import verify_commit, split_commit_message
from ..core.branch_anchor_finder import resolve_in_plain
from ..core.access_branch import ACCESS_BRANCH
from ..core.replay import load_crypto

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

    # the access branch is not code: there is nothing to pull into plain
    if branch == ACCESS_BRANCH:
        print(f"[!] '{ACCESS_BRANCH}' is the access branch (members and keys), not a code branch.")
        return

    encrypted_repo = Repo(encrypted_repo_path)
    plain_repo = Repo(plaintext_repo_path)

    # the saved repository key, if given; otherwise load_crypto decrypts it with the private key
    sym_key = None
    if sym_key_path:
        with open(sym_key_path, "rb") as sym_file:
            sym_key = sym_file.read()
        print(f"[+] Loaded AES key from {sym_key_path} ({len(sym_key)} bytes)")

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

    # members, keys and mode from the newest access state, which was just fetched
    try:
        crypto = load_crypto(encrypted_repo, owner_name, user_name, privkey_path, sym_key=sym_key)
    except Exception as e:
        print(f"[!] Could not load the keys: {e}")
        return
    sym_key, mode = crypto.sym_key, crypto.mode
    if privkey_path and not sym_key_path:
        # decrypted with the private key: save it for later pulls, as before
        out_path = Path(key_out_path) if key_out_path else Path.cwd() / "symkey.bin"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(sym_key)

    # 2. Commits on the remote branch that plain does not have yet,
    #    ordered so each parent comes before its children
    order = encrypted_repo.git.rev_list(f"{remote}/{branch}", "--not", branch,
                                        "--topo-order", "--reverse").split()
    new_commits = [encrypted_repo.commit(h) for h in order]
    if not new_commits:
        print("[+] No new commits to pull.")
        return

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

        # the author's public key, from the access state loaded by load_crypto
        username = commit.author.name
        if username not in crypto.sign_pubs:
            click.echo(f"[!] Commit {commit.hexsha[:12]} authored by unknown '{username}' — aborting.")
            plain_repo.git.checkout("-f", branch)   # back to the untouched branch
            return
        public_key = crypto.sign_pubs[username].export_key(format='DER')

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