# Blockchain-Encryption-System
This project implements a blockchain-based encryption and decryption system using AES encryption. It supports both text and voice input for encrypting and decrypting messages. The system uses a quantum-resistant key and signature for enhanced security. The encrypted messages are stored in a blockchain to ensure data integrity.

# Features:
- AES encryption and decryption of messages.
- Blockchain for storing encrypted messages.
- Quantum-resistant key generation and signature.
- Voice input support using speech recognition.


 # Key Components of the Code
 
Block Class:The Block class represents a block in the blockchain.
Each block contains:
index: The position of the block in the chain.
 previous_hash: The hash of the previous block in the chain.
 timestamp: The time when the block was created.
 encrypted_data: The AES-encrypted message data.
 proof: A proof of work used for blockchain validation.
 quantum_resistant_key: A randomly generated, secure key for encryption.
 signature: A randomly generated signature.
The calculate_hash() method creates a SHA-256 hash of the block's data for integrity verification.

Blockchain Class:
The Blockchain class manages a chain of blocks, starting with the genesis block (the first block with no predecessor).
It has methods for:
 Adding new blocks (add_block).
 Retrieving the latest block (get_latest_block).
 Validating the integrity of the blockchain (validate_chain).
 Performing Proof of Work to add new blocks (proof_of_work).
 
BlockchainEncryption Class:
This class handles encryption, decryption, and blockchain operations:
Encrypting Messages:
  It uses AES encryption (CBC mode) with a quantum-resistant key for encrypting 
  messages.
  The encrypted message is stored in the blockchain as a new block.
Decrypting Messages:
  It decrypts AES-encrypted messages using the provided AES key and 
  initialization vector (IV).
Voice Input:
  It uses the speech recognition library (speech_recognition) to capture voice 
  input for encryption.
Quantum-resistant key and signature generation:
  These are generated for each block to ensure secure encryption and blockchain 
  integrity.
  
Main Functions:
encrypt_main():
  This function initiates the encryption process. It allows the user to input a 
  message either via text or voice.
  The input message is then encrypted using AES encryption and stored in the 
  blockchain as a new block. The blockchain is validated after the encryption 
  process.
decrypt_main():
  This function handles the decryption of messages. It accepts the encrypted 
  message, AES key, IV, quantum-resistant key, and signature.
  The quantum-resistant key and signature are validated before the message is 
  decrypted.
  
# Detailed Workflow

1. Encryption Process:

The user selects whether to input the message via text or voice.
  Text Input: The user directly types the message.
  Voice Input: The user's voice is captured using the microphone, and speech 
  recognition is used to convert it to text.
A random quantum-resistant key is generated for encryption.
The message is encrypted using AES encryption (CBC mode), and the encrypted message is stored in a new block in the blockchain.
A proof of work is generated to ensure the blockchain is valid, and the new block is added to the chain.
After encryption, the user is shown the encrypted message, the AES key, IV, quantum-resistant key, and the blockchain's current state.

2. Decryption Process:

The user is prompted to input the encrypted message, AES key, IV, quantum-resistant key, and signature.
The quantum-resistant key and signature are validated (length checks in this example, but could be extended with more complex validation).
The encrypted message is decrypted using the AES key and IV.
The decrypted message is displayed along with the blockchain's state for verification.

# Security Considerations

Quantum-Resistant Key: This system uses a randomly generated alphanumeric key (64 characters) for encryption. While the key generation is secure in this context, a more robust quantum-resistance mechanism could be integrated for future-proofing against quantum attacks.

AES Encryption: AES encryption (Advanced Encryption Standard) is widely used and secure, especially when used with appropriate padding (like PKCS7) and modes like CBC (Cipher Block Chaining).

Blockchain Integrity: Each block contains a hash of the previous block, ensuring that any modification in the blockchain will break the chain. The system also uses proof of work (similar to Bitcoin) to add blocks securely, making it tamper-resistant
