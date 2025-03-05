from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import os

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=16)

def encrypt_file(input_file, output_file, password):
    if not os.path.exists(input_file):  # Check if input file exists
        raise FileNotFoundError(f"The file {input_file} does not exist.")
    
    salt = os.urandom(16)  # Generate a random salt
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC)
    
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    
    with open(output_file, 'wb') as f:
        f.write(salt)  # Store salt at the beginning
        f.write(cipher.iv)  # Store IV
        f.write(ciphertext)
    
    # Delete the original file after encryption
    os.remove(input_file)

def decrypt_file(input_file, output_file, password):
    if not os.path.exists(input_file):  # Check if encrypted file exists
        raise FileNotFoundError(f"The file {input_file} does not exist.")
    
    with open(input_file, 'rb') as f:
        salt = f.read(16)  # Read salt
        iv = f.read(16)  # Read IV
        ciphertext = f.read()
    
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    with open(output_file, 'wb') as f:
        f.write(plaintext)
    
    # Delete the encrypted file after decryption
    os.remove(input_file)

if __name__ == "__main__":
    action = input("Do you want to encrypt (E) or decrypt (D)? ").strip().lower()
    password = input("Enter password: ").encode()
    usb_path = "E:\\"  # Change this to your USB path
    
    if action == 'e':
        input_file = 'E:\\SeedPhrase.txt'  # Prompt for full file path
        encrypted_file = os.path.join(usb_path, "SeedPhrase.bin")
        try:
            encrypt_file(input_file, encrypted_file, password)
            print(f"File encrypted and saved on USB as {encrypted_file}")
        except FileNotFoundError as e:
            print(e)
    elif action == 'd':
        encrypted_file = 'E:\\SeedPhrase.bin'
        decrypted_file = os.path.join(usb_path, "SeedPhrase.txt")
        try:
            decrypt_file(encrypted_file, decrypted_file, password)
            print(f"File decrypted and saved on USB as {decrypted_file}")
        except FileNotFoundError as e:
            print(e)
    else:
        print("Invalid option. Please enter 'E' for encryption or 'D' for decryption.")