import click
from Crypto.PublicKey import ECC

@click.command()
@click.option('--privkey-out', default='private_key.der', help='the output path of private key')
@click.option('--pubkey-out', default='public_key.der', help='the output path of public key')
def generate_keys(privkey_out, pubkey_out):

    key = ECC.generate(curve='P-256')


    priv_key_der = key.export_key(format='DER')


    pub_key_der = key.public_key().export_key(format='DER')


    with open(privkey_out, 'wb') as f:
        f.write(priv_key_der)
    print(f"The private key has been saved to {privkey_out}")


    with open(pubkey_out, 'wb') as f:
        f.write(pub_key_der)
    print(f"The public key has been saved to {pubkey_out}")
