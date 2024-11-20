# Blockchain Encryption System

This project demonstrates a Blockchain Encryption System that leverages RSA for key management, AES for secure encryption/decryption, and integrates a blockchain to maintain the integrity of encrypted data. The system supports both text and voice input for encrypting messages and securely stores them in a blockchain, ensuring data tampering protection via signatures.

# Features

Blockchain-Based Data Storage: All encrypted messages are stored in a blockchain, ensuring immutability and integrity.
RSA Key Pair Generation: RSA keys (private and public) are generated and used for signing the encrypted messages.
AES Encryption: The system uses AES encryption with a quantum-resistant key for secure encryption of the message.
Proof of Work: A mining process (proof of work) is included to demonstrate how a new block is added to the blockchain.
Voice Recognition: Users can provide input via speech, utilizing the speech_recognition library for voice-to-text conversion.
Signature Verification: After decryption, the system verifies the authenticity of the message using the signature generated during encryption.

# Key Components of the Code

RSA Key Pair Generation:
The system generates an RSA private/public key pair if they do not already exist. The private key is used to sign the encrypted message, while the public key is used for signature verification.
RSA keys are stored in private_key.pem and public_key.pem.
AES Encryption/Decryption:
AES encryption is used to secure the message with a quantum-resistant key. The system encrypts the message and stores it in a blockchain. For decryption, the system verifies the signature using the RSA public key and decrypts the message with the AES key and initialization vector (IV).
Blockchain Structure:
The blockchain consists of blocks containing encrypted data, proof of work, and the signature. A proof-of-work mechanism ensures that the blockchain is secure and resistant to tampering.
Voice Recognition (Optional):
The system allows users to input messages using voice recognition (via the speech_recognition library). This voice-to-text feature enhances user interactivity.
Signature Generation & Verification:
A cryptographic signature is generated for the encrypted message using the RSA private key. This signature is used to verify the integrity of the message during the decryption process.

# Detailed Workflow

1. Key Generation:
On initialization, the system checks for the existence of RSA keys (private_key.pem and public_key.pem). If the keys don't exist, they are generated and saved for later use.
2. Message Encryption:
The user selects the input format (text or voice). The system then encrypts the message using AES with a randomly generated key.
A proof of work is computed to add a new block to the blockchain.
The encrypted message is signed using the RSA private key, and the block containing the encrypted message is added to the blockchain.
3. Blockchain Validation:
After adding a new block, the system validates the blockchain to ensure all blocks are properly linked and have not been tampered with. This ensures the integrity and authenticity of the stored encrypted data.
4. Message Decryption:
The user provides the encrypted message, AES key, IV, and signature. The system verifies the signature using the public RSA key.
If the signature is valid, the system decrypts the message using the AES key and IV.
5. Verification of Blockchain Integrity:
The blockchain is verified to ensure no tampering has occurred. If any block's hash doesn't match or if the chain is not properly linked, the system will notify the user.

# Security Considerations

RSA Key Security:
The private key should be securely stored, as it is used to sign the encrypted message. If compromised, an attacker could forge signatures and tamper with the data.
The system generates new RSA keys when they do not exist, ensuring the keys are unique to each instance of the system.
AES Key Security:
The AES key used for encrypting the message is randomly generated and securely transmitted along with the IV. The AES key and IV are required to decrypt the message, and their exposure would compromise the message’s security.
The system does not store the AES key directly; it only stores the encrypted data and signature, ensuring that only the intended recipient with the correct key can decrypt the data.
Blockchain Integrity:
The proof of work mechanism ensures that the blockchain is resistant to tampering. Each block is linked to the previous one, and altering any block would break the chain, making it easy to detect tampering.
The system uses SHA256 to hash the contents of each block, ensuring that any modifications to the data would result in a different hash and alert the user to potential data manipulation.
Voice Recognition Security:
While voice input enhances usability, it also introduces potential vulnerabilities, such as voice spoofing. The system could be further enhanced by integrating voice authentication or additional security checks to ensure the integrity of the user input.
Signature Verification:
The RSA public key is used to verify the signature, ensuring the authenticity of the encrypted message. This prevents unauthorized users from modifying or faking the encrypted data.

# Technologies Used

Python 3.x
PyCryptoDome (for cryptographic operations like RSA and AES)
SpeechRecognition (for voice input)
hashlib (for generating SHA256 hashes)
Base64 (for encoding and decoding data)
time (for timestamping blockchain entries)
Setup and Installation

Example:

Please select input format ('text' or 'voice'): text

Enter the message to encrypt: Hello, Blockchain Encryption!

Encrypted Message: <encrypted_message>

Auto-generated AES Key: <aes_key>

Initialization Vector (IV): <iv>

Message Signature: <signature>

Blockchain:
Block #0: Genesis Block (Hash: <genesis_block_hash>)
Block #1: <encrypted_message> (Hash: <block_hash>)
Validating the Blockchain

Decrypt:
Enter the Encrypted Message: <encrypted_message>

Enter the Auto-generated AES Key: <aes_key>

Enter the Initialization Vector (IV): <iv>

Enter the Signature (Hex format): <signature>

Decrypted Message: Hello, Blockchain Encryption!

Blockchain:
Block #0: Genesis Block (Hash: <genesis_block_hash>)
Block #1: <encrypted_message> (Hash: <block_hash>)

# Contributing

Feel free to fork the repository, submit pull requests, or open issues for enhancements or bug fixes.
