# Simple Password Manager Tool

Author: Mario Perhat  
Last Modified: March 29th

## Description

This is a simple password manager tool that securely stores passwords using AES encryption in GCM mode. It employs key derivation from a master password and a unique salt for each pair of password and address. Here's a breakdown of its functionality:

- **Data Storage**: Data is stored in a `.txt` file. During initialization, only the file name needs to be provided. The first pair of address and password is then saved into the database.

- **Master Password**: The tool operates with a master password, which is never stored in the database. It's crucial for all encryption and decryption processes.

- **Key Derivation**: The system derives a unique key for each pair of address and password using the master password and a random salt. This ensures security even if the same password is used multiple times.

- **Encryption**: Data is encrypted using AES in GCM mode. Each pair of address and password is encrypted with its own initialization vector (IV), which ensures uniqueness and enhances security.

- **Integrity Check**: Before decryption, an integrity check is performed by comparing the hash of the decrypted data with the stored hash. This ensures data integrity and authenticity.

- **Password Retrieval**: To retrieve a password, the corresponding line is decoded from Base64. The salt and IV are then extracted from the end of the data. If the correct master password is provided, the data is decrypted, and the password is returned.

- **Updating Passwords**: If a new password is set for an existing address, the previous record is deleted, and the new one is added to the database.

## Implementation Details

- **Key Derivation Algorithm**: PBKDF2 with HMAC SHA-256.
- **Encryption Algorithm**: AES in GCM mode.
- **Salt and IV Length**: Fixed at 16 bytes and 12 bytes, respectively.
- **Data Format**: Data is stored in the format: `address|password|hash(address|password)`.

## Usage

1. Initialize the password manager with the desired file name.
2. Store the first pair of address and password.
3. Use the provided functions to manage passwords:
   - Add new passwords.
   - Retrieve passwords for specific addresses.
   - Update existing passwords.
   
## License

This project is licensed under the [MIT License](LICENSE).
