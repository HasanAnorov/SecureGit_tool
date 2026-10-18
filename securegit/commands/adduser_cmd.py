import os
import click
import base64
from pathlib import Path
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from git import Repo
import urllib.request
import urllib.error
import json
from securegit.core.crypto_tool import ecies_encrypt_with_aesctr
from securegit.core.access_branch import ACCESS_BRANCH, read_state, write_state

@click.command()
@click.argument("enc_repo_path", type=click.Path(exists=True))
@click.option("--owner-key", "owner_key_path", required=True, help="Owner's signing private key (DER)")
@click.option("--share-name", "share_name", required=False, help="Sharee username")
@click.option("--enc-pub", "enc_pub_path", required=True, type=click.Path(exists=True), help="Sharee's encryption public key (DER)")
@click.option("--sig-pub", "sig_pub_path", required=True, type=click.Path(exists=True), help="Sharee's signing public key (DER)")
@click.option("--sym-key", "sym_key_path", required=True, type=click.Path(exists=True), help="Path to symmetric key file (binary) to encrypt for sharee")
@click.option("--token", default=None, required=False, help="GitHub token (optional)")

def securegit_adduser(enc_repo_path, owner_key_path, share_name, enc_pub_path, sig_pub_path,
                        sym_key_path, token):
    """
    Share the repository with a member: add their keys and the repository key
    encrypted for them as a new owner-signed state on the access branch.
    """

    enc_repo_path = Path(enc_repo_path).resolve()
    encrypt_repo = Repo(enc_repo_path)

    # --- detect repo owner from remote url ---
    try:
        origin = encrypt_repo.remotes.origin
        remote_url = list(origin.urls)[0]
        if remote_url.startswith("git@"):
            parts = remote_url.split(":")[1].replace(".git", "").split("/")
        else:
            parts = remote_url.replace(".git", "").split("/")
        repo_owner = parts[-2] if len(parts) >= 2 else None
        repo_name = parts[-1] if len(parts) >= 2 else None
    except Exception:
        click.echo("[!] No 'origin' remote found; cannot determine repo owner.")
        repo_owner = None
        remote_url = None
        repo_name = None

    if not share_name:
        click.echo(f"[*] No share-name provided, defaulting to repo owner: {repo_owner}")
        share_name = repo_owner

    # start from the newest access state and add this member's three files
    state = read_state(encrypt_repo)
    with open(enc_pub_path, "rb") as f:
        enc_pub_der = f.read()
    with open(sig_pub_path, "rb") as f:
        state[f"shareinfo/{share_name}_sign_pub.der"] = f.read()
    with open(sym_key_path, "rb") as f:
        sym_key_data = f.read()
    state[f"shareinfo/{share_name}_enc_pub.der"] = enc_pub_der
    state[f"shareinfo/{share_name}_keycipher.bin"] = ecies_encrypt_with_aesctr(enc_pub_der, sym_key_data)

    # the encryption mode travels with the access state, once it is known
    config_path = enc_repo_path / "securegit_config.json"
    if config_path.exists():
        state["securegit_config.json"] = config_path.read_bytes()

    # owner's signature over the shareinfo/ files in path order, as before
    h = SHA256.new()
    for path in sorted(state):
        if path.startswith("shareinfo/"):
            h.update(state[path])
    with open(owner_key_path, "rb") as f:
        key = ECC.import_key(f.read())
    signature = DSS.new(key, "fips-186-3").sign(h)
    state["shareinfo.sig"] = base64.b64encode(signature)

    commit = write_state(encrypt_repo, state, f"access: add {share_name}")
    click.echo(f"[+] Added '{share_name}' to the access branch '{ACCESS_BRANCH}' (state {commit[:12]})")
    click.echo(f"[*] Share it with: securegit push {enc_repo_path} origin {ACCESS_BRANCH}")


    try:
        origin = encrypt_repo.remotes.origin
        remote_url = list(origin.urls)[0]
    except Exception:
        click.echo("[!] No 'origin' remote found; cannot auto-invite.")
        remote_url = None

    if not token:
        return

    if remote_url:
        # parse owner/repo from remote_url
        # handle formats:
        # https://github.com/owner/repo.git
        # git@github.com:owner/repo.git
        if remote_url.startswith("git@"):
            # git@github.com:owner/repo.git
            parts = remote_url.split(":")[1].replace(".git", "").split("/")
        else:
            parts = remote_url.replace(".git", "").split("/")
        if len(parts) >= 2:
            owner = parts[-2]
            repo_name = parts[-1]
            api_url = f"https://api.github.com/repos/{owner}/{repo_name}/collaborators/{share_name}"
            data = json.dumps({"permission": "push"}).encode("utf-8")
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
                "Content-Type": "application/json"
            }
            if owner == share_name:
                return
            req = urllib.request.Request(api_url, data=data, headers=headers, method="PUT")
            try:
                with urllib.request.urlopen(req) as resp:
                    if resp.status in (201, 204):
                        if resp.status == 201:
                            click.echo(f"[+] GitHub invite sent.")
                        if resp.status == 204:
                            click.echo(f"[+] Already collaborator.")
                    else:
                        click.echo(f"[!] Failed to invite: {resp.status} {resp.read().decode()}")
            except urllib.error.HTTPError as e:
                click.echo(f"[!] HTTP error: {e.code} {e.read().decode()}")
            except Exception as e:
                click.echo(f"[!] Error while inviting: {e}")
        else:
            click.echo("[!] Unexpected remote URL format; cannot determine owner/repo.")
    else:
        click.echo("[!] Skipping invite: no origin or no token provided.")