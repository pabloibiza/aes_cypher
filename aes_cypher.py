import hashlib
from Crypto.Cipher import AES
import os
import argparse
import getpass

HELP_TEXT = """
AES File Encryptor/Decryptor
===============================
This script allows you to encrypt and decrypt files using AES256 encryption in CBC mode.
It uses a user-provided key, which is hashed to ensure it meets the AES key length requirements.

Usage:
python aes_cypher.py [-e <input_file>] [-d <input_file>] [-v <iv>]
-h            : Show this help message.
-e <file>     : Encrypt the specified file.
-d <file>     : Decrypt the specified file.
-v <hex>      : Specify the initialization vector (IV) in hexadecimal format for decryption.
"""


# Padding function to ensure data is a multiple of 16 bytes.
def pad(data):
    padding_length = 16 - len(data) % 16
    padding = bytes([padding_length] * padding_length)
    return data + padding

# Unpadding function to remove padding from decrypted data.
def unpad(data):
    padding_length = data[-1]
    if padding_length < 1 or padding_length > 16:
        raise ValueError("Invalid padding encountered")
    return data[:-padding_length]


# Encrypts the input file and writes the encrypted data to the output_file. Returns the hex-encoded iv and output file name.
def encrypt_file (input_file, key_plain):
    key = hashlib.sha256(key_plain.encode()).digest()
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    try:
        # Read the input file
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        # Create header with original filename
        base_name = os.path.basename(input_file)
        header = len(base_name).to_bytes(4, 'big') + base_name.encode('utf-8')
        
        # Combine header and plaintext, pad, and encrypt
        data = header + plaintext
        padded_data = pad(data)
        ciphertext = cipher.encrypt(padded_data)

        encoded_iv = iv.hex()
        output_file_name = f"{base_name}_iv{encoded_iv}.enc"
        with open(output_file_name, 'wb') as f:
            f.write(ciphertext)
        return encoded_iv, output_file_name
    except Exception as e:
        print(f"An error ocurred during encryption: {e}")
        return None, None

# Decrypts the input file and writes the decrypted data to the output_file.
def decrypt_file(key_plain, iv, input_file):
    try:
        decode_key = hashlib.sha256(key_plain.encode()).digest()
        if len(decode_key) != 32:
            raise ValueError("Incorrect AES length")
        cipher = AES.new(decode_key, AES.MODE_CBC, iv)
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()
        decrypted_padded = cipher.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_padded)
        
        # Extract original filename from header
        name_len = int.from_bytes(decrypted_data[:4], 'big')
        original_name = decrypted_data[4:4+name_len].decode('utf-8')
        content = decrypted_data[4+name_len:]
        
        with open(original_name, 'wb') as f:
            f.write(content)
        return original_name
    except Exception as e:
        # Remove the output file in case it was created.
        if os.path.exists(original_name):
            os.remove(original_name)
        print(f"An error ocurred during decryption: {e}")
        raise #Re-raise the exception so it can be caught by the caller method.


def main():
    parser = argparse.ArgumentParser(description="AES File Encryptor/Decryptor", add_help=False)
    parser.add_argument('-h', action='store_true', help='Show help message')
    parser.add_argument('-e', metavar='<input_file>', help='Encrypt the specified file')
    parser.add_argument('-d', metavar='<input_file>', help='Decrypt the specified file')
    parser.add_argument('-v', metavar='<iv>', required=False, help='Initialization vector (hex) for decryption')

    args = parser.parse_args()

    if args.h or not (args.e or args.d):
        print(HELP_TEXT)
        return

    if args.e and args.d:
        print("Error: Cannot specify both -e and -d at the same time. Use -h for help.")
        return

    input_file = args.e or args.d
    if not input_file:
        print("Error: Must specify an input file with -e or -d. Use -h for help.")
        return

    # Prompt for password
    key = getpass.getpass("Enter encryption key: ")

    if args.e:
        encoded_iv, output_file_name = encrypt_file(input_file, key)
        if encoded_iv and output_file_name:
            print(f"File encrypted successfully.\nIV: {encoded_iv}")
        else:
            print("Error encrypting the file.")

    elif args.d:
        if not args.v:
            print("Error: You must specify the IV in hexadecimal (-v) for decryption.")
            print(HELP_TEXT)
            return
        try:
            iv_bytes = bytes.fromhex(args.v)
        except ValueError:
            print("Error: The IV must be in hexadecimal format.")
            return
        try:
            output_file_name = decrypt_file(key, iv_bytes, input_file)
            print(f"File decrypted successfully.\nOutput file: {output_file_name}")
        except Exception as e:
            print(f"Error decrypting the file: {e}")

if __name__ == "__main__":
    main()