from git import Repo
from gitdb.exc import BadName


def resolve_in_plain(enc_repo: Repo, plain_repo: Repo, cipher_hexsha: str):
    """Return the plaintext commit that corresponds to cipher_hexsha.

    The two repos store the same commit under different hashes, so the commit
    is located by its position in the history instead: a route starting from a
    branch both repos share, e.g. 'main~4^2'.
    """

    anchors = [head.name for head in plain_repo.heads]
    if not anchors:
        raise ValueError("plaintext repo has no branches to locate commits from")

    refs = [f"--refs=refs/heads/{name}" for name in anchors]
    route = enc_repo.git.name_rev(*refs, "--name-only", cipher_hexsha)
    if route == "undefined":
        raise ValueError(f"cipher commit {cipher_hexsha[:12]} is not reachable "
                         f"from any plaintext branch {anchors}")

    try:
        plain_commit = plain_repo.commit(route)
    except (BadName, ValueError):
        raise ValueError(f"plaintext repo does not match the encrypted history: "
                         f"route {route} does not exist in it; it may have diverged")

    # guard function disabled, this could help only when the structure of two repos diverge
    # _check_same_commit(enc_repo.commit(cipher_hexsha), plain_commit)
    return plain_commit


# def _check_same_commit(cipher_commit, plain_commit):
#     """Stop if the plaintext commit found doesn't look like the cipher one."""
#     parts = cipher_commit.message.split("|")
#     cipher_msg = parts[1] if len(parts) >= 3 else cipher_commit.message.rstrip("\n")
#     plain_msg = plain_commit.message.rstrip("\n")
#
#     if cipher_msg != plain_msg or len(cipher_commit.parents) != len(plain_commit.parents):
#         raise ValueError(f"plaintext repo does not match the encrypted history at "
#                          f"{cipher_commit.hexsha[:12]}; it may have diverged")