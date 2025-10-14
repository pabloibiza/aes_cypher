# AES File Encryptor/Decryptor

This script allows you to encrypt and decrypt files using AES256 encryption in CBC mode. It embeds the original filename in the encrypted file, so decryption restores the original name even if the encrypted file is renamed.

## Features

- AES256 encryption in CBC mode
- Password-based key derivation (hashed with SHA256)
- Interactive password prompt (password not echoed)
- Automatic output filename generation for encryption
- Original filename preservation in encrypted files

## Requirements

- Python 3.x
- PyCryptoDome library (`pip install pycryptodome`)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/pabloibiza/aes_cypher.git
   cd aes_cypher
   ```

2. Install dependencies:
   ```bash
   pip install pycryptodome
   ```

3. Make the script executable:
   ```bash
   chmod +x aes_cypher.py
   ```

## Usage

### Encryption
```bash
./aes_cypher.py -e <input_file>
```
- Prompts for encryption key
- Outputs: `<input_file>_iv<iv_hex>.enc`
- Displays the IV for later decryption

### Decryption
```bash
./aes_cypher.py -d <encrypted_file> -v <iv_hex>
```
- Prompts for decryption key
- Outputs: Original filename (restored from encrypted file)
- Requires the IV from encryption

### Help
```bash
./aes_cypher.py -h
```

## Example

1. Create a test file:
   ```bash
   echo "Secret data" > secret.txt
   ```

2. Encrypt:
   ```bash
   ./aes_cypher.py -e secret.txt
   # Enter encryption key: mypassword
   # Output: secret.txt_iv<iv>.enc
   ```

3. Decrypt (even if renamed):
   ```bash
   mv secret.txt_iv<iv>.enc renamed.enc
   ./aes_cypher.py -d renamed.enc -v <iv>
   # Enter encryption key: mypassword
   # Output: secret.txt
   ```

## Security Notes

- Uses SHA256 to hash the password for key generation
- Random IV for each encryption
- Password is not stored or logged
- Encrypted files include original filename for restoration

## License

See LICENSE file.

## Author

pabloibiza</content>
<parameter name="filePath">/workspaces/aes_cypher/README.md