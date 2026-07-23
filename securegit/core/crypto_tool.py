import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from .Git_command import *
from Crypto.Protocol.KDF import HKDF
import struct



# def derive_aes_key_from_password(password: str, salt: bytes = None, key_length: int = 32) -> bytes:
#     """
#     Derive password using HKDF-SHA-256
#
#     :param password: the input password
#     :param salt: if not provided, randomly generate
#     :param key_length: 16 for AES-128，24 for AES-192，32 for AES-256, default 32
#     :return: the AES key
#     """
#     if salt is None:
#         salt = os.urandom(16)
#
#     password_bytes = password.encode("utf-8")
#
#     hkdf = HKDF(
#         algorithm=hashes.SHA256(),
#         length=key_length,
#         salt=salt,
#         info=b"AES Key Derivation", # optional
#     )
#     aes_key = hkdf.derive(password_bytes)
#
#     return aes_key, salt

#aes_private_key = b'atfwus_test_0011'

# password = 'my_secure_password'
#
# salt = b'12345'
#
# aes_private_key, salt = derive_aes_key_from_password(password, salt)

def ecies_encrypt_with_aesctr(recipient_pub_der: bytes, plaintext: bytes) -> bytes:
    """
    ECIES-like encryption:
    - generate ephemeral ECC key (P-256)
    - ECDH to get shared secret
    - HKDF(shared_secret) -> 32-byte aes key
    - AES-CTR encrypt plaintext with encrypt_aes
    - pack: 4-byte length(ephemeral_pub_der) || ephemeral_pub_der || ciphertext
    Returns bytes.
    """
    recipient_pub = ECC.import_key(recipient_pub_der)
    eph_key = ECC.generate(curve="P-256")

    # ECDH: shared_secret = x coordinate of (recipient_pub * eph_priv)
    # compute shared point: recipient_pub.pointQ * eph_key.d
    shared_point = recipient_pub.pointQ * eph_key.d
    shared_x = int(shared_point.x)  # big integer

    # convert to fixed-length bytes (P-256 -> 32 bytes)
    shared_secret = shared_x.to_bytes(32, "big")

    # derive AES key via HKDF-SHA256
    aes_key = HKDF(master=shared_secret, key_len=32, salt=None, hashmod=SHA256, context=b"ecies-aes-ctr")

    # encrypt with provided encrypt_aes
    ciphertext = encrypt_aes(plaintext, aes_key)

    eph_pub_der = eph_key.public_key().export_key(format="DER")
    packed = struct.pack(">I", len(eph_pub_der)) + eph_pub_der + ciphertext
    return packed

def ecies_decrypt_with_aesctr(recipient_priv_der: bytes, packed: bytes) -> bytes:
    """
    Unpack and decrypt data produced by ecies_encrypt_with_aesctr.
    Expects packed = 4-byte len || ephemeral_pub_der || ciphertext
    """
    if len(packed) < 4:
        raise ValueError("Invalid packed ECIES data")
    eph_len = struct.unpack(">I", packed[:4])[0]
    if 4 + eph_len > len(packed):
        raise ValueError("Invalid ephemeral key length")
    eph_pub_der = packed[4:4+eph_len]
    ciphertext = packed[4+eph_len:]

    eph_pub = ECC.import_key(eph_pub_der)
    recipient_priv = ECC.import_key(recipient_priv_der)

    # ECDH: shared_secret = x coordinate of (eph_pub.pointQ * recipient_priv.d)
    shared_point = eph_pub.pointQ * recipient_priv.d
    shared_x = int(shared_point.x)
    shared_secret = shared_x.to_bytes(32, "big")

    aes_key = HKDF(master=shared_secret, key_len=32, salt=None, hashmod=SHA256, context=b"ecies-aes-ctr")

    plaintext = decrypt_aes(ciphertext, aes_key)
    return plaintext

# def securegit_decrypt_share(share_dir, enc_priv_path, out_path):
#     """
#     Decrypt a shareinfo/{username}/keycipher using sharer's encryption private key.
#     """
#     share_dir = Path(share_dir).resolve()
#     keycipher_path = share_dir / "keycipher"
#     if not keycipher_path.exists():
#         raise click.ClickException(f"[!] keycipher not found at {keycipher_path}")
#
#     packed = keycipher_path.read_bytes()
#     with open(enc_priv_path, "rb") as f:
#         enc_priv_der = f.read()
#
#     try:
#         sym_key = ecies_decrypt_with_aesctr(enc_priv_der, packed)
#     except Exception as e:
#         raise click.ClickException(f"[!] Decryption failed: {e}")
#
#     out_path = Path(out_path).resolve()
#     out_path.parent.mkdir(parents=True, exist_ok=True)
#     out_path.write_bytes(sym_key)
#     click.echo(f"[+] Decrypted symmetric key written to {out_path}")

def encrypt_aes(data, aes_private_key):
    iv = get_random_bytes(16)

    ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))

    key = aes_private_key.ljust(32, b'\0')[:32]

    # use AES CTR
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    ct = cipher.encrypt(data)

    return iv + ct


def decrypt_aes(ct, aes_private_key):
    iv = ct[:16]

    key = aes_private_key.ljust(32, b'\0')[:32]

    ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))

    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    pt = cipher.decrypt(ct[16:])

    return pt


def generate_Signature(commit, sign_key):
    data_bytes, committer_time, commit_message = get_commit_bytes(commit)

    # print('data_bytes:', data_bytes)

    # Hash the data using SHA-256
    data_hash_obj = SHA256.new(data_bytes)
    # print('hash value:', data_hash_obj.hexdigest())

    # Create a signature using ECDSA (private key)
    signer = DSS.new(sign_key, 'fips-186-3')
    signature = signer.sign(data_hash_obj)
    # print("signature:", signature.hex())

    sigma_str = base64.b64encode(signature).decode('utf-8')

    merged_str = committer_time + "|" + commit_message + "|" + sigma_str

    return merged_str

def get_origin_bytes(commit, commit_time, commit_message):
    # Get parent commit hash
    parent_hashes = [parent.hexsha for parent in commit.parents] if commit.parents else [b'']

    # Get tree hash
    tree_hash = commit.tree.hexsha

    # Get author information
    author_name = commit.author.name
    author_email = commit.author.email
    author_time = commit.authored_date

    # Get committer information
    committer_name = commit.committer.name
    committer_email = commit.committer.email
    committer_time = commit_time

    parent_hashes = [parent.hexsha for parent in commit.parents]

    parent_hashes_str = ', '.join(parent_hashes)

    result_str = (
        f"parents: {parent_hashes_str}, "
        f"tree: {tree_hash}, "
        f"author: {author_name} <{author_email}>, {author_time}, "
        f"committer: {committer_name} <{committer_email}>, {committer_time}, "
        f"message: {commit_message}"
    )

    # transform to bytes
    result_bytes = result_str.encode('utf-8')
    # print("current_msg:", result_str)

    #print(result_bytes)

    return result_bytes

def verify_commit(commit, public_key):
    try:
        public_key = ECC.import_key(public_key)

        separated_msg = commit.message.split('|')
        if len(separated_msg) < 3:
            print(
                f"[!] Invalid commit format for {commit.hexsha}: expected 'msg|origin|signature', got {commit.message}")
            print(f"[!] Signature verification fails due to invalid update!")
            return False

        try:
            msg_bytes = get_origin_bytes(commit, separated_msg[0], separated_msg[1])
        except Exception as e:
            print(f"[!] Failed to reconstruct message for {commit.hexsha}: {e}")
            print(f"[!] Signature verification fails due to invalid update!")
            return False

        try:
            signature = base64.b64decode(separated_msg[2].encode('utf-8'))
        except Exception as e:
            print(f"[!] Failed to decode signature for {commit.hexsha}: {e}")
            print(f"[!] Signature verification fails due to invalid update!")
            return False

        verifier = DSS.new(public_key, 'fips-186-3')

        hash_obj = SHA256.new(msg_bytes)

        try:
            verifier.verify(hash_obj, signature)
            print(f"[!] Signature of {commit.hexsha} is valid!")
            return True
        except ValueError:
            print(f"[!] Signature verification fails due to invalid update!")
            return False
    except Exception as e:
        print(f"[!] Unexpected error while verifying commit {commit.hexsha}: {e}")
        return False

    #print("recovered signature:", signature.hex())


    #print('current hash value:', hash_obj.hexdigest())



def verify_publickey(publickey, commit):
    h = SHA256.new()

    try:
        folder_tree = commit.tree / "shareinfo"
    except KeyError:
        raise FileNotFoundError(f"Folder publickey not found in commit {commit.hexsha}")

    try:
        signature_file = commit.tree / "shareinfo.sig"
    except KeyError:
        raise FileNotFoundError(f"The signature of publickeys not found in commit {commit.hexsha}")

    signature = signature_file.data_stream.read()
    # print(signature)

    # GitPython Tree order
    for blob in sorted(folder_tree.traverse(), key=lambda b: b.path):
        if blob.type == 'blob':
            content = blob.data_stream.read()
            h.update(content)
    # print(h.hexdigest())

    signature = base64.b64decode(signature)

    verifier = DSS.new(publickey, 'fips-186-3')

    try:
        verifier.verify(h, signature)
        print("[+] Signature on sharees' public keys is valid.")
        return True
    except ValueError:
        print("[-] Signature on sharees' public keys is invalid!")
        return False

def test():
    data = '12345'

    #ciphertext = base64.b64encode(encrypt_aes(data.encode()))
    #print("Encrypted:", ciphertext)

    path = 'path'
    #
    #
    # repo = Repo(path)
    #
    # commit = repo.commit('9f4cbe')
    #
    with open(path, "rb") as public_file:
        key = public_file.read()
    print(type(key))
    #
    # verify_publickey(owner_public_key, commit)



    # # Enc
    # ciphertext = encrypt_aes(data)
    # print("Encrypted:", ciphertext)
    #
    # with open('example_dec.py', 'ab') as sf:
    #     sf.write(ciphertext)
    #
    # # Dec
    # plaintext = decrypt_aes(ciphertext)
    # print("Decrypted:", plaintext.decode())

    # password = "my_secure_password"
    # aes_key, salt = derive_aes_key_from_password(password)
    #
    # print(type(password))
    # print(type(aes_key))
    #
    # print(f"Derived AES Key: {aes_key.hex()}")
    # print(f"Salt: {salt.hex()}")

    # pass
if __name__ == '__main__':
   test()
