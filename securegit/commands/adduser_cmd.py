import os
import click
import base64
from pathlib import Path
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from git import Repo
import shutil
import urllib.request
import urllib.error
import json
from securegit.core.crypto_tool import ecies_encrypt_with_aesctr

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
    Sign the 'public key' folder in encrypted repo using DSS (fips-186-3).
    A base64 signature will be written to 'publickey.sig'.
    """

    enc_repo_path = Path(enc_repo_path).resolve()
    encrypt_repo = Repo(enc_repo_path)
    shareinfo_dir = enc_repo_path / "shareinfo"
    shareinfo_dir.mkdir(parents=True, exist_ok=True)

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

    dest_enc_pub = shareinfo_dir / f"{share_name}_enc_pub.der"
    dest_sig_pub = shareinfo_dir / f"{share_name}_sign_pub.der"
    shutil.copyfile(enc_pub_path, dest_enc_pub)
    shutil.copyfile(sig_pub_path, dest_sig_pub)

    click.echo(f"[+] Copied encryption pubkey -> {dest_enc_pub}")
    click.echo(f"[+] Copied signing pubkey -> {dest_sig_pub}")

    with open(sym_key_path, "rb") as f:
        sym_key_data = f.read()

    with open(enc_pub_path, "rb") as f:
        enc_pub_der = f.read()

    packed = ecies_encrypt_with_aesctr(enc_pub_der, sym_key_data)

    keycipher_path = shareinfo_dir / f"{share_name}_keycipher.bin"

    with open(keycipher_path, "wb") as f:
        f.write(packed)
    click.echo(f"[+] Encrypted symmetric key written to {keycipher_path}")

    sig_file = enc_repo_path / "shareinfo.sig"

    encrypt_repo.git.add("-A")

    h = SHA256.new()

    for entry in sorted(encrypt_repo.index.entries.keys()):
        path = entry[0]
        if path.startswith("shareinfo/"):
            blob = encrypt_repo.index.entries[entry][1]  # blob id
            obj = encrypt_repo.odb.stream(blob)
            h.update(obj.read())

    # print("hash value:", h.hexdigest())

    with open(owner_key_path, "rb") as f:
        key = ECC.import_key(f.read())

    signer = DSS.new(key, "fips-186-3")
    signature = signer.sign(h)
    sigma_str = base64.b64encode(signature).decode("utf-8")

    # print('signature:', sigma_str)

    with open(sig_file, "w") as f:
        f.write(sigma_str)

    click.echo(f"[+] Signature written to {sig_file}")

    encrypt_repo.git.add("-A")


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