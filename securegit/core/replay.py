import json
from dataclasses import dataclass
from pathlib import Path
from Crypto.PublicKey import ECC
from git import Repo, Actor
from .Git_command import get_git_diff_name
from .repo_operation import dec_patch_diff, dec_line_diff
from .crypto_tool import verify_commit, verify_publickey, ecies_decrypt_with_aesctr
from .branch_anchor_finder import resolve_in_plain

@dataclass
class CryptoContext:
    """Everything needed to verify and decrypt commits."""
    sym_key: bytes
    mode: str
    owner_public_key: object
    sign_pubs: dict


def load_crypto(enc_repo: Repo, owner_name, sharee_name, sharee_privkey):
    """Find the sharee's access info, verify it, and decrypt the symmetric key.

    Moved from clone_cmd.py. Raises ValueError instead of printing and
    returning, so the calling command decides how to report errors.
    """
    # shareinfo_commit - the commit that contains keycipher for decryption of commits
    shareinfo_commit = None
    try:
        _ = enc_repo.head.commit.tree / "shareinfo" / f"{sharee_name}_keycipher.bin"
        shareinfo_commit = enc_repo.head.commit
    except KeyError:
        # HEAD lacks keycipher: scan every branch, newest commit first
        for commit in enc_repo.iter_commits(all=True):
            try:
                _ = commit.tree / "shareinfo" / f"{sharee_name}_keycipher.bin"
                shareinfo_commit = commit
                break
            except KeyError:
                continue

    if shareinfo_commit is None:
        raise ValueError(f"No commit in this repo contains 'shareinfo/{sharee_name}_keycipher.bin'. "
                         f"Either the repo was never shared with '{sharee_name}', or the sharee_name is wrong.")

    # sign_pubs - needed only when a commit lacks the shareinfo folder
    sign_pubs = {}
    for blob in (shareinfo_commit.tree / "shareinfo").traverse():
        if blob.type == 'blob' and blob.name.endswith("_sign_pub.der"):
            username = blob.name[:-len("_sign_pub.der")]
            sign_pubs[username] = ECC.import_key(blob.data_stream.read())

    # owner's sign pub is needed to verify shareinfo.sig
    if owner_name not in sign_pubs:
        raise ValueError(f"Owner '{owner_name}' not in shareinfo of commit "
                         f"{shareinfo_commit.hexsha[:12]} — aborting.")
    owner_public_key = sign_pubs[owner_name]

    if not verify_publickey(owner_public_key, shareinfo_commit):
        raise ValueError(f"shareinfo.sig verification FAILED for commit "
                         f"{shareinfo_commit.hexsha[:12]} — aborting.")

    with open(sharee_privkey, "rb") as priv_file:
        user_priv_key = priv_file.read()
    enc_key = (shareinfo_commit.tree / "shareinfo" / f"{sharee_name}_keycipher.bin").data_stream.read()
    sym_key = ecies_decrypt_with_aesctr(user_priv_key, enc_key)

    config_path = Path(enc_repo.working_tree_dir) / "securegit_config.json"
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        mode = json.load(f).get("mode")

    return CryptoContext(sym_key, mode, owner_public_key, sign_pubs)


def build_branch(enc_repo: Repo, plain_repo: Repo, branch_ref: str, branch_name: str,
                 crypto: CryptoContext):
    """Replay the cipher commits of branch_ref into the plaintext repo and name
    the result branch_name. Returns the new plaintext tip, or None if there was
    nothing to replay.

    Moved from clone_cmd.py; behaviour unchanged.
    """
    # branches plain already has; their commits are built, so skip them.
    # only names the cipher repo also knows, or rev-list would fail on them
    enc_names = {h.name for h in enc_repo.heads}
    built = [h.name for h in plain_repo.heads if h.name in enc_names]

    # the requested branch only, minus what is already built,
    # ordered so each parent comes before its children
    order = enc_repo.git.rev_list(branch_ref, "--not", *built, "--topo-order", "--reverse").split()

    commits = [enc_repo.commit(h) for h in order]
    if not commits:
        return None
    print(f"[+] Found {len(commits)} commits to replay.")

    plain_path = plain_repo.working_tree_dir

    # cipher commit hash -> the plaintext commit corresponding to it,
    # used to resolve a commit's parents and to position the working tree
    plain_of = {}

    def plain_for(cipher_hexsha):
        """The plaintext commit for a cipher commit.

        Commits replayed in this run are already in plain_of. One built by an
        earlier run is not, so it is located by its position in the history.
        """
        if cipher_hexsha not in plain_of:
            plain_of[cipher_hexsha] = resolve_in_plain(enc_repo, plain_repo, cipher_hexsha)
        return plain_of[cipher_hexsha]

    for idx, commit in enumerate(commits, start=1):
        print(f"[{idx}/{len(commits)}] Replaying encrypted commit {commit.hexsha[:12]} ...")

        # the author's public key: from this commit's shareinfo if it has one,
        # otherwise from the sign_pubs collected by load_crypto
        username = commit.author.name
        public_key = None
        try:
            if verify_publickey(crypto.owner_public_key, commit):
                public_file = commit.tree / "shareinfo" / f"{username}_sign_pub.der"
                public_key = public_file.data_stream.read()
        except (KeyError, FileNotFoundError):
            pass

        if public_key is None:
            if username not in crypto.sign_pubs:
                raise ValueError(f"Commit {commit.hexsha[:12]} authored by unknown "
                                 f"'{username}' — aborting.")
            public_key = crypto.sign_pubs[username].export_key(format='DER')

        if not verify_commit(commit, public_key):
            raise ValueError(f"Signature check failed for commit {commit.hexsha[:12]} — aborting.")

        # the patch applies to this commit's first parent, so put that on disk first
        if commit.parents:
            target = plain_for(commit.parents[0].hexsha)
            if plain_repo.head.is_valid() and plain_repo.head.commit != target:
                plain_repo.git.checkout(target.hexsha)

        diff_info = get_git_diff_name(enc_repo, commit.hexsha)
        print(diff_info)
        if crypto.mode == 'char':
            dec_patch_diff(plain_path, diff_info, commit, crypto.sym_key)
        else:
            dec_line_diff(plain_path, diff_info, commit, crypto.sym_key)

        plain_repo.git.add("-A")

        # commit in the plaintext repo, mirroring the original message and author
        separated_msg = commit.message.split('|')
        author = Actor(commit.author.name, commit.author.email)
        committer = Actor(commit.committer.name, commit.committer.email)
        parents = [plain_for(p.hexsha) for p in commit.parents]
        # Use same message; dates can be preserved via env vars, but we’ll keep it simple
        new_commit = plain_repo.index.commit(
            separated_msg[1],
            author=author,
            committer=committer,
            parent_commits=parents,
        )
        plain_of[commit.hexsha] = new_commit
        print(f"    -> plaintext commit {new_commit.hexsha[:12]} created.")

    # name the plaintext tip after the branch we replayed, then check it out
    tip = plain_for(enc_repo.commit(branch_ref).hexsha)
    plain_repo.create_head(branch_name, tip.hexsha, force=True)
    print(f"[+] Created plaintext branch '{branch_name}'")
    plain_repo.git.checkout(branch_name)
    return tip