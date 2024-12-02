from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes, padding as sym_padding
import base64
from utils import load_key, load_transmitted_data

#function for decrypting AES encrypted message using provided key and IV
def aes_decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)) #create AES cipeher in CBC (cipher block chaining) mode with key and IV
    decryptor = cipher.decryptor() #decryptor object
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder() #unpadder object
    padded_message = decryptor.update(ciphertext) + decryptor.finalize() #decrypts ciphertext into padded plaintext
    return unpadder.update(padded_message) + unpadder.finalize() #remove padding to retrieve original plaintext

#function for verifying the integrity of an encrypted message
def verify_mac(data, key, mac):
    #HMAC object using AES eky and SHA256 hashing, update hmac with encrypted data and check generated HMAC with provided MAC using verify
    hmac = HMAC(key, hashes.SHA256())
    hmac.update(data)
    hmac.verify(mac)

#receiver function to perform receiver actions
def receiver():
    #load receiver's private RSA key from the pem file
    receiver_private_key = load_key("receiver_private.pem", is_private=True)

    #load transmitted data
    encrypted_aes_key, iv, encrypted_message, mac = load_transmitted_data()

    #decrypt AES key using receiver's private RSA key and OAEP padding
    aes_key = receiver_private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    #verify MAC 
    verify_mac(encrypted_message, aes_key, mac)

    #decrypt message and print to the console
    message = aes_decrypt(encrypted_message, aes_key, iv)
    print("Decrypted Message:", message.decode())

if __name__ == "__main__":
    receiver()
