import click
from git import Repo
from ..core.crypto_tool import generate_Signature
from Crypto.PublicKey import ECC


@click.command()
@click.argument("plaintext_repo_path")
@click.argument("encrypted_repo_path")
@click.argument("msg")
@click.argument("private_key_path")
def securegit_commit(plaintext_repo_path, encrypted_repo_path, msg, private_key_path):
    """
    securegit commit <plaintext_repo_path> <encrypted_repo_path> <msg> <private_key_path>
    """

    with open(private_key_path, "rb") as f:
        priv_key_data = f.read()
    sign_key = ECC.import_key(priv_key_data)


    plaintext_repo = Repo(plaintext_repo_path)
    plaintext_repo.git.commit('-m', f"{msg}")
    plain_commit = plaintext_repo.commit('HEAD')
    print(f"[+] plain repo commit finished, commit id: {plain_commit.hexsha}")


    encrypted_repo = Repo(encrypted_repo_path)
    # cipher_commit = encrypted_repo.index.commit(msg)

    encrypted_repo.git.commit('-m', f"{msg}")


    commit_cipher = encrypted_repo.commit('HEAD')
    signature = generate_Signature(commit_cipher, sign_key)

    # new_commit = encrypted_repo.index.commit(
    #     signature,
    #     head=True
    # )


    encrypted_repo.git.commit('--amend', '--allow-empty', '-m', f"{signature}")

    print(f"[+] cipher repo commit finished, commit msg: {signature}")
