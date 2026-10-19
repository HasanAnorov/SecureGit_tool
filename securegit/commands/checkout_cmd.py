import click
from git import Repo, GitCommandError
from ..core.replay import load_crypto, build_branch
from ..core.access_branch import ACCESS_BRANCH

def _recorded(plain_repo, key):
    """A value clone recorded in plain's .git/config, as text ('' if missing)."""
    try:
        return plain_repo.config_reader().get("securegit", key)
    except Exception:
        return ""

def _branch_to_build(plain_repo, enc_repo, args):
    """Return (branch_ref, branch_name) when args name a branch that exists only
    in the encrypted repo and must be built in plain first; otherwise None."""
    if len(args) != 1:
        return None                          # e.g. '-b new': plain git checkout
    name = args[0]
    if name in [h.name for h in plain_repo.heads]:
        return None                          # already built: ordinary checkout
    if name in [h.name for h in enc_repo.heads]:
        return name, name                    # cipher has it as a local branch
    for remote in enc_repo.remotes:
        for ref in remote.refs:
            if ref.remote_head == name:
                return str(ref), name        # cipher knows it only as origin/<name>
    return None                              # not a branch (file, commit id): let git decide

@click.command(name="checkout", context_settings=dict(ignore_unknown_options=True))
@click.argument("plaintext_repo_path")
@click.argument("encrypted_repo_path")
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
@click.option("--owner", "owner_name", default=None, help="Repository owner (default: recorded by clone)")
@click.option("--user", "user_name", default=None, help="Your user name (default: recorded by clone)")
@click.option("--sym-key", "sym_key_path", default=None, help="Saved repository key file (default: recorded by clone)")
@click.option("--private-key", "privkey_path", default=None, help="Your private key, to decrypt the repository key instead")
def securegit_checkout(plaintext_repo_path, encrypted_repo_path, args, owner_name, user_name, sym_key_path, privkey_path):
    """
    Secure version of 'git checkout'.
    Behaves like 'git checkout', but runs on both plaintext and encrypted repos.
    """

    # the access branch is not code: never build it, create it (-b) or reset it (-B)
    if ACCESS_BRANCH in args:
        click.echo(f"[!] '{ACCESS_BRANCH}' is the access branch (members and keys), not a code branch.")
        return

    plain_repo = Repo(plaintext_repo_path)
    enc_repo = Repo(encrypted_repo_path)

    # a branch that exists only in the encrypted repo must be built in plain first
    target = _branch_to_build(plain_repo, enc_repo, args)
    if target is not None:
        branch_ref, branch_name = target

        # building replays commits and stages everything, so uncommitted work
        # in plain would be swept into someone else's commit
        if plain_repo.is_dirty(untracked_files=True):
            click.echo("[!] Plaintext repo has uncommitted changes. "
                       "Commit or stash them before checking out a branch that must be built.")
            return

        # keys: options first, otherwise what clone recorded
        owner_name = owner_name or _recorded(plain_repo, "owner")
        user_name = user_name or _recorded(plain_repo, "user")
        if not privkey_path:
            sym_key_path = sym_key_path or _recorded(plain_repo, "symkey")
        if not owner_name or not user_name or not (sym_key_path or privkey_path):
            click.echo(f"[!] '{branch_name}' must be built from the encrypted repo, but the keys are unknown. "
                       "Run again with --owner NAME --user NAME --sym-key FILE (or --private-key FILE).")
            return

        try:
            sym_key = None
            if sym_key_path:
                with open(sym_key_path, "rb") as f:
                    sym_key = f.read()
            crypto = load_crypto(enc_repo, owner_name, user_name, privkey_path, sym_key=sym_key)
        except Exception as e:
            click.echo(f"[!] Could not load the keys: {e}")
            return

        # step off the current branch: replayed commits go to whatever HEAD points at,
        # and building must not move the branch the user is on
        original = plain_repo.head.commit.hexsha if plain_repo.head.is_detached else plain_repo.active_branch.name
        plain_repo.git.checkout("--detach")
        try:
            build_branch(enc_repo, plain_repo, branch_ref, branch_name, crypto)
        except Exception as e:
            click.echo(f"[!] Building '{branch_name}' failed: {e}")
            plain_repo.git.checkout("-f", original)   # back to where the user was
            return
        click.echo(f"[✓] Built plaintext branch '{branch_name}'")
        # the ordinary checkout below now switches both repos to the new branch

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
