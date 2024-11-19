import hashlib
import random
import string
import time
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets  # For generating secure random keys
import speech_recognition as sr  # Library for voice recognition

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


# Blockchain class
class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        # Genesis block with no previous hash
        genesis_block = Block(0, "0", time.time(), "Genesis Block", 100, "None", "None")
        self.chain.append(genesis_block)

    def add_block(self, encrypted_data, proof, quantum_resistant_key, signature):
        previous_block = self.chain[-1]
        new_block = Block(len(self.chain), previous_block.hash, time.time(), encrypted_data, proof, quantum_resistant_key, signature)
        self.chain.append(new_block)
        return new_block

    def get_latest_block(self):
        return self.chain[-1]

    def validate_chain(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                print(f"Block #{current_block.index} has been tampered with!")
                return False

            if current_block.previous_hash != previous_block.hash:
                print(f"Block #{current_block.index} is not linked properly!")
                return False

        print("Blockchain is valid!")
        return True

    def proof_of_work(self, previous_proof):
        proof = 0
        while not self.is_valid_proof(previous_proof, proof):
            proof += 1
        return proof

    def is_valid_proof(self, previous_proof, proof):
        guess = f'{previous_proof}{proof}'.encode('utf-8')
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"


# BlockchainEncryption class to handle AES encryption and blockchain operations
class BlockchainEncryption:
    def __init__(self):
        self.blockchain = Blockchain()

    def generate_random_key(self, length=32):
        """Generate a secure random key for quantum-resistant encryption."""
        return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))

    def encrypt_message(self, message):
        # Generate a random 32-character quantum-resistant key for AES encryption
        key = self.generate_random_key(32)
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)
        encrypted_data = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')  # Base64 encoded IV for storage
        encrypted_message = base64.b64encode(encrypted_data).decode('utf-8')

        previous_proof = self.blockchain.get_latest_block().proof
        proof = self.blockchain.proof_of_work(previous_proof)

        # Generate random quantum-resistant key and signature
        quantum_resistant_key = self.generate_random_key(64)  # 64-character alphanumeric key
        signature = self.generate_random_key(128)  # 128-character alphanumeric signature

        # Add encrypted message to the blockchain
        self.blockchain.add_block(encrypted_message, proof, quantum_resistant_key, signature)
        return encrypted_message, key, iv, quantum_resistant_key, signature

    def get_voice_input(self, timeout=5):
        """Get voice input from the user."""
        recognizer = sr.Recognizer()
        microphone = sr.Microphone()

        print("Please say something...")

        # Listen for 5 seconds
        with microphone as source:
            recognizer.adjust_for_ambient_noise(source)
            try:
                audio = recognizer.listen(source, timeout=timeout)
                message = recognizer.recognize_google(audio)
                print(f"User said: {message}")
                return message
            except sr.WaitTimeoutError:
                print("No speech detected within the timeout period.")
                return None
            except sr.UnknownValueError:
                print("Sorry, I could not understand your speech.")
                return None


# Main function to handle encryption
def encrypt_main():
    print("Blockchain Encryption System")

    # Initialize BlockchainEncryption object
    blockchain_encryption = BlockchainEncryption()

    # Ask the user whether they want to input via text or voice
    input_choice = input("Please select input format ('text' or 'voice'): ").strip().lower()

    if input_choice == "text":
        message = input("Enter the message to encrypt: ")
    elif input_choice == "voice":
        message = blockchain_encryption.get_voice_input()
        if not message:
            print("No input received, exiting...")
            return
    else:
        print("Invalid choice! Please enter 'text' or 'voice'.")
        return

    # Encrypt the message
    encrypted_message, key, iv, quantum_resistant_key, signature = blockchain_encryption.encrypt_message(message)
    print(f"Encrypted Message: {encrypted_message}")
    print(f"Auto-generated AES Key: {key}")
    print(f"Initialization Vector (IV): {iv}")
    print(f"Quantum Resistant Key: {quantum_resistant_key}")
    print(f"Signature: {signature}")

    # Show the entire blockchain
    for block in blockchain_encryption.blockchain.chain:
        print(f"Block #{block.index}: {block.encrypted_data} (Hash: {block.hash})")

    # Validate the blockchain
    blockchain_encryption.blockchain.validate_chain()


if __name__ == "__main__":
    encrypt_main()


