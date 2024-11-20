import hashlib
import random
import string
import time
import base64
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import secrets  # For generating secure random keys
import speech_recognition as sr  # Library for voice recognition


# Generate RSA private and public keys if they don't already exist
def generate_keys():
    if not os.path.exists('private_key.pem') or not os.path.exists('public_key.pem'):
        print("Generating RSA keys...")
        key = RSA.generate(2048)

        private_key = key.export_key()
        with open("private_key.pem", "wb") as private_file:
            private_file.write(private_key)

        public_key = key.publickey().export_key()
        with open("public_key.pem", "wb") as public_file:
            public_file.write(public_key)

        print("RSA keys have been generated and saved as private_key.pem and public_key.pem")
    else:
        print("RSA keys already exist.")

# Block class to represent each block in the blockchain
class Block:
    def __init__(self, index, previous_hash, timestamp, encrypted_data, proof, signature):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.encrypted_data = encrypted_data
        self.proof = proof
        self.signature = signature
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f'{self.index}{self.previous_hash}{self.timestamp}{self.encrypted_data}{self.proof}{self.signature}'
        return hashlib.sha256(block_string.encode('utf-8')).hexdigest()

# Blockchain class
class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        # Genesis block with no previous hash
        genesis_block = Block(0, "0", time.time(), "Genesis Block", 100, "0")
        self.chain.append(genesis_block)

    def add_block(self, encrypted_data, proof, signature):
        previous_block = self.chain[-1]
        new_block = Block(len(self.chain), previous_block.hash, time.time(), encrypted_data, proof, signature)
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
        generate_keys()  # Generate keys if not already present

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

        # Generate signature for the encrypted message
        signature = self.generate_signature(encrypted_message)

        # Add encrypted message and signature to the blockchain
        self.blockchain.add_block(encrypted_message, proof, signature)
        return encrypted_message, key, iv, signature

    def generate_signature(self, encrypted_message):
        private_key = RSA.import_key(open("private_key.pem").read())  # Load private key securely

        # Create a SHA256 hash of the encrypted message
        hash_message = SHA256.new(encrypted_message.encode())

        # Sign the hashed message with the private key
        signer = pkcs1_15.new(private_key)
        signature = signer.sign(hash_message)

        return signature

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

    def decrypt_message(self, encrypted_message, aes_key, iv):
        """Decrypt the AES-encrypted message."""
        cipher = AES.new(aes_key.encode('utf-8'), AES.MODE_CBC, base64.b64decode(iv.encode('utf-8')))
        decrypted_data = unpad(cipher.decrypt(base64.b64decode(encrypted_message.encode('utf-8'))), AES.block_size)
        return decrypted_data.decode('utf-8')

    def verify_signature(self, encrypted_message, signature):
        """Verify the signature of the encrypted message."""
        public_key = RSA.import_key(open("public_key.pem").read())  # Load the public key

        # Create a SHA256 hash of the encrypted message
        hash_message = SHA256.new(encrypted_message.encode())

        try:
            pkcs1_15.new(public_key).verify(hash_message, signature)
            print("Signature is valid.")
            return True
        except (ValueError, TypeError):
            print("Signature is not valid.")
            return False

    def get_message_from_user(self):
        """Get encrypted message, AES key, IV, and signature from user."""
        encrypted_message = input("Enter the encrypted message: ")
        aes_key = input("Enter the AES key: ")
        iv = input("Enter the IV: ")
        signature_hex = input("Enter the signature (hex): ")
        signature = bytes.fromhex(signature_hex)
        return encrypted_message, aes_key, iv, signature


# Main function to handle both encryption and decryption
def main():
    print("Blockchain Encryption/Decryption System")

    blockchain_encryption = BlockchainEncryption()

    action_choice = input("Choose action (encrypt/decrypt): ").strip().lower()

    if action_choice == "encrypt":
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
        encrypted_message, key, iv, signature = blockchain_encryption.encrypt_message(message)
        print(f"Encrypted Message: {encrypted_message}")
        print(f"Auto-generated AES Key: {key}")
        print(f"Initialization Vector (IV): {iv}")
        print(f"Message Signature: {signature.hex()}")

        # Show the entire blockchain
        for block in blockchain_encryption.blockchain.chain:
            print(f"Block #{block.index}: {block.encrypted_data} (Hash: {block.hash})")

        # Validate the blockchain
        blockchain_encryption.blockchain.validate_chain()

    elif action_choice == "decrypt":
        encrypted_message, aes_key, iv, signature = blockchain_encryption.get_message_from_user()

        # Verify the signature
        if not blockchain_encryption.verify_signature(encrypted_message, signature):
            return

        # Decrypt the message
        decrypted_message = blockchain_encryption.decrypt_message(encrypted_message, aes_key, iv)
        print(f"Decrypted Message: {decrypted_message}")

    else:
        print("Invalid choice! Please enter 'encrypt' or 'decrypt'.")


if __name__ == "__main__":
    main()
