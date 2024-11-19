import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import secrets  # For generating secure random keys

# Block class to represent each block in the blockchain
class Block:
    def __init__(self, index, previous_hash, timestamp, encrypted_data, proof, quantum_resistant_key, signature):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.encrypted_data = encrypted_data
        self.proof = proof
        self.quantum_resistant_key = quantum_resistant_key
        self.signature = signature
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f'{self.index}{self.previous_hash}{self.timestamp}{self.encrypted_data}{self.proof}{self.quantum_resistant_key}{self.signature}'
        return hashlib.sha256(block_string.encode('utf-8')).hexdigest()


# Blockchain class to represent the blockchain and manage blocks
class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        # Genesis block with no previous hash
        genesis_block = Block(0, "0", 0, "Genesis Block", 100, "None", "None")
        self.chain.append(genesis_block)

    def add_block(self, encrypted_data, proof, quantum_resistant_key, signature):
        previous_block = self.chain[-1]
        new_block = Block(len(self.chain), previous_block.hash, 0, encrypted_data, proof, quantum_resistant_key, signature)
        self.chain.append(new_block)
        return new_block

    def get_latest_block(self):
        return self.chain[-1]


# BlockchainEncryption class to handle AES decryption and blockchain operations
class BlockchainEncryption:
    def __init__(self):
        self.blockchain = Blockchain()

    def decrypt_message(self, encrypted_message, aes_key, iv):
        """Decrypt the AES-encrypted message."""
        cipher = AES.new(aes_key.encode('utf-8'), AES.MODE_CBC, base64.b64decode(iv.encode('utf-8')))
        decrypted_data = unpad(cipher.decrypt(base64.b64decode(encrypted_message.encode('utf-8'))), AES.block_size)
        return decrypted_data.decode('utf-8')

    def validate_quantum_resistant_key(self, quantum_resistant_key):
        """Validates the quantum-resistant key (this can be a placeholder check)."""
        # Here we can add validation logic to verify quantum-resistant key (e.g., length check or pattern check).
        return len(quantum_resistant_key) == 64  # Example check for length

    def validate_signature(self, signature):
        """Validates the signature (this can be a placeholder check)."""
        # Here we can add logic to validate the signature (e.g., using RSA or ECDSA for verification).
        return len(signature) == 128  # Example check for length


# Main function to handle decryption
def decrypt_main():
    print("Blockchain Decryption System")

    # Take inputs from the user (encrypted message, AES key, IV, quantum-resistant key, and signature)
    encrypted_message = input("Enter the Encrypted Message: ").strip()
    aes_key = input("Enter the Auto-generated AES Key: ").strip()
    iv = input("Enter the Initialization Vector (IV): ").strip()
    quantum_resistant_key = input("Enter the Quantum Resistant Key: ").strip()
    signature = input("Enter the Signature: ").strip()

    # Initialize BlockchainEncryption object
    blockchain_encryption = BlockchainEncryption()

    # Validate quantum-resistant key and signature
    if not blockchain_encryption.validate_quantum_resistant_key(quantum_resistant_key):
        print("Invalid Quantum Resistant Key!")
        return

    if not blockchain_encryption.validate_signature(signature):
        print("Invalid Signature!")
        return

    # Decrypt the message using the AES key and IV
    decrypted_message = blockchain_encryption.decrypt_message(encrypted_message, aes_key, iv)
    print(f"Decrypted Message: {decrypted_message}")

    # Show the entire blockchain
    for block in blockchain_encryption.blockchain.chain:
        print(f"Block #{block.index}: {block.encrypted_data} (Hash: {block.hash})")


if __name__ == "__main__":
    decrypt_main()
