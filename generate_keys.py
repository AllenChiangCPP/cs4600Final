from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

#function for generating RSA keys
def generate_rsa_keys():
    #generate RSA private eky using public exponent 65536 of key size 2048 for security
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    #generate corresponding public key from generated private key
    public_key = private_key.public_key()
    return private_key, public_key

#function for saving private or public keys to a file
def save_key(key, filename, is_private=False):
    #open file as wb
    with open(filename, 'wb') as f:
        #check if key is private, save in standard format and unencrypted
        if is_private:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        #else, key is assumed to be public and saved in standard format
        else:
            f.write(
                key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

if __name__ == "__main__":
    #generate the sender's public and private keys and receiver's public and private keys
    sender_private, sender_public = generate_rsa_keys()
    receiver_private, receiver_public = generate_rsa_keys()

    #save the generated keys to .pem files for later use
    save_key(sender_private, "sender_private.pem", is_private=True)
    save_key(sender_public, "sender_public.pem")
    save_key(receiver_private, "receiver_private.pem", is_private=True)
    save_key(receiver_public, "receiver_public.pem")
