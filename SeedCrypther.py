import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2

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
    
    try:
        with open(input_file, 'rb') as f:
            salt = f.read(16)  # Read salt
            iv = f.read(16)  # Read IV
            ciphertext = f.read()
        
        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        try:
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        except ValueError:
            raise ValueError("Decryption failed. Possible reasons:\n"
                             "1. Incorrect password\n"
                             "2. File has been modified\n"
                             "3. Incompatible encryption method")
        
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        
        # Delete the encrypted file after decryption
        os.remove(input_file)
    
    except Exception as e:
        print(f"Decryption error: {e}")
        sys.exit(1)

def check_usb_drive():
    # List of potential USB drive letters
    possible_drives = ['E:', 'F:', 'G:', 'H:', 'I:', 'J:', 'K:']
    
    for drive in possible_drives:
        if os.path.exists(drive + '\\'):
            return drive + '\\'
    
    return None

def list_files(directory):
    try:
        files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        return files
    except Exception as e:
        print(f"Error listing files: {e}")
        return []

def get_decrypted_filename(filename):
    """
    Handle files with two extensions, always keeping first extension and replacing second
    """
    # Split the filename
    parts = filename.split('.')
    
    # If filename doesn't have at least two extensions, handle it
    if len(parts) < 2:
        return filename + '.txt'
    
    # Replace the second extension with 'txt'
    parts[-1] = 'txt'
    
    # Join back
    return '.'.join(parts)

def main():
    # Check USB drive availability
    usb_path = check_usb_drive()
    
    if not usb_path:
        print("No USB drive found. Please insert a USB drive and try again.")
        sys.exit(1)
    
    print(f"USB drive found at: {usb_path}")
    
    # List files on the USB drive
    files = list_files(usb_path)
    print("\nFiles on the USB drive:")
    for i, file in enumerate(files, 1):
        print(f"{i}. {file}")
    
    # User input for action
    action = input("\nDo you want to encrypt (E) or decrypt (D)? ").strip().lower()
    
    # Multiple password attempts
    max_attempts = 3
    for attempt in range(max_attempts):
        password = input("Enter password: ").encode()
        
        if action == 'e':
            # File selection for encryption
            file_index = int(input("Enter the number of the file to encrypt: ")) - 1
            input_file = os.path.join(usb_path, files[file_index])
            encrypted_file = os.path.join(usb_path, files[file_index] + ".bin")
            
            try:
                encrypt_file(input_file, encrypted_file, password)
                print(f"File encrypted and saved on USB as {encrypted_file}")
                break
            except FileNotFoundError as e:
                print(e)
        
        elif action == 'd':
            # File selection for decryption
            file_index = int(input("Enter the number of the file to decrypt: ")) - 1
            encrypted_file = os.path.join(usb_path, files[file_index])
            
            # Ensure only .bin files can be decrypted
            if not encrypted_file.lower().endswith('.bin'):
                print("Please select a .bin encrypted file.")
                sys.exit(1)
            
            # Generate decrypted filename with two extensions, replacing second
            decrypted_filename = get_decrypted_filename(files[file_index].replace('.bin', ''))
            decrypted_file = os.path.join(usb_path, decrypted_filename)
            
            try:
                decrypt_file(encrypted_file, decrypted_file, password)
                print(f"File decrypted and saved on USB as {decrypted_file}")
                break
            except ValueError as e:
                print(str(e))
                if attempt < max_attempts - 1:
                    print(f"Attempt {attempt + 1} failed. {max_attempts - attempt - 1} attempts remaining.")
                else:
                    print("Max password attempts reached. Exiting.")
                    sys.exit(1)
        
        else:
            print("Invalid option. Please enter 'E' for encryption or 'D' for decryption.")
            sys.exit(1)
if __name__ == "__main__":
    main()