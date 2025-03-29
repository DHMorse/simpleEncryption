# SimpleEncryption 🔐

A secure and user-friendly command-line tool for RSA encryption and decryption of messages. This project provides a simple interface for generating key pairs, encrypting messages, and decrypting them using asymmetric encryption.

## Features ✨

- 🔑 Generate RSA key pairs for secure communication
- 🔒 Encrypt messages using public/private keys
- 🔓 Decrypt messages using private keys
- 📁 Automatic file management for keys and messages
- 🎨 Colored terminal output for better user experience
- 🛡️ Secure key storage and message handling

## Requirements 📋

- Python 3.10 or higher
- Required Python packages:
  - cryptography
  - termcolor

## Installation 🚀

1. Clone the repository:
```bash
git clone https://github.com/yourusername/simpleEncryption.git
cd simpleEncryption
```

2. Install the required packages:
```bash
pip install -r requirements.txt
```

## Usage 💡

Run the program:
```bash
python src/main.py
```

The program provides an interactive menu with the following options:

1. **Generate Keys**: Create RSA key pairs for two users
   - Enter the names of both users
   - Keys will be saved in the `keys` directory

2. **Encrypt**: Encrypt a message using a selected key
   - Choose from available keys
   - Enter your message
   - Encrypted message will be saved in the `messages` directory

3. **Decrypt**: Decrypt a message using a private key
   - Choose from available keys
   - Select the encrypted message to decrypt
   - Decrypted message will be saved as a text file

4. **Exit**: Close the program

## Security 🔒

- Uses RSA-2048 encryption with OAEP padding
- SHA-256 for message digest
- Secure key storage in PEM format
- No hardcoded keys or sensitive data

## Project Structure 📁

```
simpleEncryption/
├── keys            # Directory for storing RSA key pairs
├── messages        # Directory for storing encrypted/decrypted
├── src            # Source code directory
│   ├── constants.py  # Global constants and directory setup
│   ├── helpers.py    # Helper functions for encryption/decryption
│   └── main.py       # Main program with CLI interface
├── LICENSE        # GNU General Public License v3.0
├── pyproject.toml # Project metadata and dependencies
├── README.md      # Project documentation
├── requirements.txt # Python package dependencies
└── uv.lock        # Lock file for uv package manager
```

## License 📄

This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.

## Contributing 🤝

Contributions are welcome! Please feel free to submit a Pull Request.