import os
from io import BytesIO
from gitdb import IStream

ACCESS_BRANCH = "securegit-access"


def latest_state(enc_repo):
    """The newest access state: the local branch if there is one, else the copy
    fetched from the server. None if the repo has no access branch yet."""
    for ref in (ACCESS_BRANCH, f"origin/{ACCESS_BRANCH}"):
        try:
            return enc_repo.commit(ref)
        except Exception:
            continue
    return None


def read_state(enc_repo):
    """Files of the newest access state as {path: bytes}; {} if there is none."""
    state = latest_state(enc_repo)
    if state is None:
        return {}
    return {blob.path: blob.data_stream.read()
            for blob in state.tree.traverse() if blob.type == "blob"}


def write_state(enc_repo, files, message):
    """Record files ({path: bytes}) as a new commit on the access branch, on top
    of the newest state, without touching the working tree or the real index."""
    parent = latest_state(enc_repo)
    index_file = os.path.join(enc_repo.git_dir, "securegit-access.index")
    try:
        with enc_repo.git.custom_environment(GIT_INDEX_FILE=index_file):
            enc_repo.git.read_tree("--empty")
            for path, data in sorted(files.items()):
                blob = enc_repo.odb.store(IStream("blob", len(data), BytesIO(data)))
                enc_repo.git.update_index("--add", "--cacheinfo", f"100644,{blob.hexsha.decode()},{path}")
            tree = enc_repo.git.write_tree()
    finally:
        if os.path.exists(index_file):
            os.remove(index_file)

    parents = ["-p", parent.hexsha] if parent is not None else []
    commit = enc_repo.git.commit_tree(tree, *parents, "-m", message)

    # move the local branch, but only if nobody moved it meanwhile
    try:
        old = enc_repo.commit(ACCESS_BRANCH).hexsha
    except Exception:
        old = ""
    enc_repo.git.update_ref(f"refs/heads/{ACCESS_BRANCH}", commit, old)
    return commit