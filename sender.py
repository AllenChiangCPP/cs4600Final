from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes, padding as sym_padding
import os
import base64
from utils import load_key, save_transmitted_data

#function for encrypting a message with a given key
def aes_encrypt(message, key):
    iv = os.urandom(16) #generate random 16 byte initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)) #create AES cipher in CBC mode
    encryptor = cipher.encryptor() #craete encrypter object
    #pad message to AES block size (128 bits)
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder() 
    padded_message = padder.update(message) + padder.finalize() 
    ciphertext = encryptor.update(padded_message) + encryptor.finalize() #encrypt padded message and return IV and cipertext
    return iv, ciphertext

#function for generating MAC for given data using AES key
def generate_mac(data, key):
    hmac = HMAC(key, hashes.SHA256()) #create HMAC object using AES key and SHA256 hash algorithm
    hmac.update(data) #add data to HMAC
    return hmac.finalize() #generate and return MAC

#sender function to perform sender actions
def sender():
    #generate random 356 bit AES key
    aes_key = os.urandom(32)

    #load receiver's public RSA key from the receive_public.pem file
    receiver_public_key = load_key("receiver_public.pem", is_private=False)

    #encrypt AES key using receiver's RSA public key with OAEP padding to add randomness for security
    encrypted_aes_key = receiver_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    #reads palintext message from file
    with open("message.txt", "rb") as f:
        message = f.read()

    #encrypt message using AES and random iv
    iv, encrypted_message = aes_encrypt(message, aes_key)

    #generate MAC using encrypted meessage and AES key
    mac = generate_mac(encrypted_message, aes_key)

    #Save transmitted data encrypted aes key, iv, encrypted message, and mac
    save_transmitted_data(encrypted_aes_key, iv, encrypted_message, mac)

if __name__ == "__main__":
    sender()
