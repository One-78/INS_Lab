
import os
import time
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

AES_KEY_DIR = "keys/aes/"
RSA_KEY_DIR = "keys/rsa/"
OUTPUT_DIR = "output/"
INPUT_DIR = "input/"

def initialize_directories():
    os.makedirs(AES_KEY_DIR, exist_ok=True)
    os.makedirs(RSA_KEY_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(INPUT_DIR, exist_ok=True)

def generate_aes_key(key_size):
    key_file = f"{AES_KEY_DIR}aes_{key_size}.key"
    if not os.path.exists(key_file):
        key = get_random_bytes(key_size // 8)
        with open(key_file, 'wb') as f:
            f.write(key)
        print(f"AES-{key_size} key generated and saved to {key_file}")
    else:
        print(f"AES-{key_size} key already exists at {key_file}")

def load_aes_key(key_size):
    key_file = f"{AES_KEY_DIR}aes_{key_size}.key"
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        print("Key file not found. Generating new key...")
        generate_aes_key(key_size)
        return load_aes_key(key_size)

def read_input_file(filename):
    filepath = os.path.join(INPUT_DIR, filename)
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found in input directory")
        return None

    with open(filepath, 'rb') as f:
        return f.read()

def aes_encrypt_ecb_file(input_filename, key_size):
    start_time = time.time()

    plaintext_bytes = read_input_file(input_filename)
    if plaintext_bytes is None:
        return None

    key = load_aes_key(key_size)
    cipher = AES.new(key, AES.MODE_ECB)

    padded_plaintext = pad(plaintext_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)

    output_file = f"{OUTPUT_DIR}aes_{key_size}_ecb_{input_filename}.enc"
    with open(output_file, 'wb') as f:
        f.write(ciphertext)

    end_time = time.time()
    execution_time = end_time - start_time

    print(f"Encryption completed using AES-{key_size} ECB mode")
    print(f"Input file: {INPUT_DIR}{input_filename}")
    print(f"Encrypted data saved to {output_file}")
    print(f"Execution time: {execution_time:.6f} seconds")

    return execution_time

def aes_encrypt_ecb(plaintext, key_size):
    start_time = time.time()

    key = load_aes_key(key_size)
    cipher = AES.new(key, AES.MODE_ECB)

    plaintext_bytes = plaintext.encode('utf-8')
    padded_plaintext = pad(plaintext_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)

    output_file = f"{OUTPUT_DIR}aes_{key_size}_ecb_encrypted.bin"
    with open(output_file, 'wb') as f:
        f.write(ciphertext)

    end_time = time.time()
    execution_time = end_time - start_time

    print(f"Encryption completed using AES-{key_size} ECB mode")
    print(f"Encrypted data saved to {output_file}")
    print(f"Execution time: {execution_time:.6f} seconds")

    return execution_time

def aes_decrypt_ecb_file(encrypted_filename, key_size):
    start_time = time.time()

    key = load_aes_key(key_size)
    cipher = AES.new(key, AES.MODE_ECB)

    input_file = os.path.join(OUTPUT_DIR, encrypted_filename)
    if not os.path.exists(input_file):
        print(f"Error: Encrypted file '{input_file}' not found")
        return None

    with open(input_file, 'rb') as f:
        ciphertext = f.read()

    decrypted_padded = cipher.decrypt(ciphertext)
    decrypted = unpad(decrypted_padded, AES.block_size)

    output_file = f"{OUTPUT_DIR}aes_{key_size}_ecb_decrypted.txt"
    with open(output_file, 'wb') as f:
        f.write(decrypted)

    end_time = time.time()
    execution_time = end_time - start_time

    print(f"Decryption completed using AES-{key_size} ECB mode")
    print(f"Decrypted data saved to {output_file}")
    print("Decrypted content preview:")
    print(decrypted.decode('utf-8', errors='replace')[:500])
    print(f"Execution time: {execution_time:.6f} seconds")

    return execution_time

def aes_decrypt_ecb(key_size):
    start_time = time.time()

    key = load_aes_key(key_size)
    cipher = AES.new(key, AES.MODE_ECB)

    input_file = f"{OUTPUT_DIR}aes_{key_size}_ecb_encrypted.bin"
    with open(input_file, 'rb') as f:
        ciphertext = f.read()

    decrypted_padded = cipher.decrypt(ciphertext)
    decrypted = unpad(decrypted_padded, AES.block_size)

    end_time = time.time()
    execution_time = end_time - start_time

    print(f"Decryption completed using AES-{key_size} ECB mode")
    print(f"Decrypted message: {decrypted.decode('utf-8')}")
    print(f"Execution time: {execution_time:.6f} seconds")

    return execution_time

def aes_encrypt_cfb_file(input_filename, key_size):
    start_time = time.time()

    plaintext_bytes = read_input_file(input_filename)
    if plaintext_bytes is None:
        return None

    key = load_aes_key(key_size)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)

    ciphertext = cipher.encrypt(plaintext_bytes)

    output_file = f"{OUTPUT_DIR}aes_{key_size}_cfb_{input_filename}.enc"
    with open(output_file, 'wb') as f:
        f.write(iv + ciphertext)

    end_time = time.time()
    execution_time = end_time - start_time

    print(f"Encryption completed using AES-{key_size} CFB mode")
    print(f"Input file: {INPUT_DIR}{input_filename}")
    print(f"Encrypted data saved to {output_file}")
    print(f"Execution time: {execution_time:.6f} seconds")

    return execution_time

def aes_encrypt_cfb(plaintext, key_size):
    start_time = time.time()

    key = load_aes_key(key_size)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)

    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext = cipher.encrypt(plaintext_bytes)

    output_file = f"{OUTPUT_DIR}aes_{key_size}_cfb_encrypted.bin"
    with open(output_file, 'wb') as f:
        f.write(iv + ciphertext)

    end_time = time.time()
    execution_time = end_time - start_time

    print(f"Encryption completed using AES-{key_size} CFB mode")
    print(f"Encrypted data saved to {output_file}")
    print(f"Execution time: {execution_time:.6f} seconds")

    return execution_time

def aes_decrypt_cfb_file(encrypted_filename, key_size):
    start_time = time.time()

    key = load_aes_key(key_size)

    input_file = os.path.join(OUTPUT_DIR, encrypted_filename)
    if not os.path.exists(input_file):
        print(f"Error: Encrypted file '{input_file}' not found")
        return None

    with open(input_file, 'rb') as f:
        data = f.read()

    iv = data[:AES.block_size]
    ciphertext = data[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    decrypted = cipher.decrypt(ciphertext)

    output_file = f"{OUTPUT_DIR}aes_{key_size}_cfb_decrypted.txt"
    with open(output_file, 'wb') as f:
        f.write(decrypted)

    end_time = time.time()
    execution_time = end_time - start_time

    print(f"Decryption completed using AES-{key_size} CFB mode")
    print(f"Decrypted data saved to {output_file}")
    print("Decrypted content preview:")
    print(decrypted.decode('utf-8', errors='replace')[:500])
    print(f"Execution time: {execution_time:.6f} seconds")

    return execution_time

def aes_decrypt_cfb(key_size):
    start_time = time.time()

    key = load_aes_key(key_size)

    input_file = f"{OUTPUT_DIR}aes_{key_size}_cfb_encrypted.bin"
    with open(input_file, 'rb') as f:
        data = f.read()

    iv = data[:AES.block_size]
    ciphertext = data[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    decrypted = cipher.decrypt(ciphertext)

    end_time = time.time()
    execution_time = end_time - start_time

    print(f"Decryption completed using AES-{key_size} CFB mode")
    print(f"Decrypted message: {decrypted.decode('utf-8')}")
    print(f"Execution time: {execution_time:.6f} seconds")

    return execution_time

def generate_rsa_key(key_size):
    key_file = f"{RSA_KEY_DIR}rsa_{key_size}_private.pem"
    pub_key_file = f"{RSA_KEY_DIR}rsa_{key_size}_public.pem"

    if not os.path.exists(key_file):
        key = RSA.generate(key_size)

        with open(key_file, 'wb') as f:
            f.write(key.export_key('PEM'))

        with open(pub_key_file, 'wb') as f:
            f.write(key.publickey().export_key('PEM'))

        print(f"RSA-{key_size} key pair generated")
        print(f"Private key saved to {key_file}")
        print(f"Public key saved to {pub_key_file}")
    else:
        print(f"RSA-{key_size} key pair already exists")

def load_rsa_private_key(key_size):
    key_file = f"{RSA_KEY_DIR}rsa_{key_size}_private.pem"
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return RSA.import_key(f.read())
    else:
        print(f"Key file not found. Generating new key pair...")
        generate_rsa_key(key_size)
        return load_rsa_private_key(key_size)

def load_rsa_public_key(key_size):
    key_file = f"{RSA_KEY_DIR}rsa_{key_size}_public.pem"
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return RSA.import_key(f.read())
    else:
        print("Key file not found. Generating new key pair...")
        generate_rsa_key(key_size)
        return load_rsa_public_key(key_size)

def rsa_encrypt(plaintext, key_size):
    start_time = time.time()

    from Crypto.Cipher import PKCS1_OAEP

    public_key = load_rsa_public_key(key_size)
    cipher = PKCS1_OAEP.new(public_key)

    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext = cipher.encrypt(plaintext_bytes)

    output_file = f"{OUTPUT_DIR}rsa_{key_size}_encrypted.bin"
    with open(output_file, 'wb') as f:
        f.write(ciphertext)

    end_time = time.time()
    execution_time = end_time - start_time

    print(f"RSA-{key_size} encryption completed")
    print(f"Encrypted data saved to {output_file}")
    print(f"Execution time: {execution_time:.6f} seconds")

    return execution_time

def rsa_decrypt(key_size):
    start_time = time.time()

    from Crypto.Cipher import PKCS1_OAEP

    private_key = load_rsa_private_key(key_size)
    cipher = PKCS1_OAEP.new(private_key)

    input_file = f"{OUTPUT_DIR}rsa_{key_size}_encrypted.bin"
    with open(input_file, 'rb') as f:
        ciphertext = f.read()

    decrypted = cipher.decrypt(ciphertext)

    end_time = time.time()
    execution_time = end_time - start_time

    print(f"RSA-{key_size} decryption completed")
    print(f"Decrypted message: {decrypted.decode('utf-8')}")
    print(f"Execution time: {execution_time:.6f} seconds")

    return execution_time

def rsa_sign_file(input_filename, key_size):
    start_time = time.time()

    message_bytes = read_input_file(input_filename)
    if message_bytes is None:
        return None

    private_key = load_rsa_private_key(key_size)

    hash_obj = SHA256.new(message_bytes)
    signature = pkcs1_15.new(private_key).sign(hash_obj)

    signature_file = f"{OUTPUT_DIR}rsa_{key_size}_{input_filename}.sig"

    with open(signature_file, 'wb') as f:
        f.write(signature)

    end_time = time.time()
    execution_time = end_time - start_time

    print(f"RSA-{key_size} signature generated")
    print(f"Input file: {INPUT_DIR}{input_filename}")
    print(f"Signature saved to {signature_file}")
    print(f"Execution time: {execution_time:.6f} seconds")

    return execution_time

def rsa_sign(message, key_size):
    start_time = time.time()

    private_key = load_rsa_private_key(key_size)

    message_bytes = message.encode('utf-8')
    hash_obj = SHA256.new(message_bytes)
    signature = pkcs1_15.new(private_key).sign(hash_obj)

    message_file = f"{OUTPUT_DIR}rsa_{key_size}_message.txt"
    signature_file = f"{OUTPUT_DIR}rsa_{key_size}_signature.bin"

    with open(message_file, 'w') as f:
        f.write(message)

    with open(signature_file, 'wb') as f:
        f.write(signature)

    end_time = time.time()
    execution_time = end_time - start_time

    print(f"RSA-{key_size} signature generated")
    print(f"Message saved to {message_file}")
    print(f"Signature saved to {signature_file}")
    print(f"Execution time: {execution_time:.6f} seconds")

    return execution_time

def rsa_verify_file(input_filename, signature_filename, key_size):
    start_time = time.time()

    public_key = load_rsa_public_key(key_size)

    message_bytes = read_input_file(input_filename)
    if message_bytes is None:
        return None

    signature_path = os.path.join(OUTPUT_DIR, signature_filename)
    if not os.path.exists(signature_path):
        print(f"Error: Signature file '{signature_path}' not found")
        return None

    with open(signature_path, 'rb') as f:
        signature = f.read()

    hash_obj = SHA256.new(message_bytes)

    pkcs1_15.new(public_key).verify(hash_obj, signature)

    end_time = time.time()
    execution_time = end_time - start_time

    print(f"RSA-{key_size} signature verification completed")
    print("Signature is VALID")
    print(f"Execution time: {execution_time:.6f} seconds")

    return execution_time

def rsa_verify(key_size):
    start_time = time.time()

    public_key = load_rsa_public_key(key_size)

    message_file = f"{OUTPUT_DIR}rsa_{key_size}_message.txt"
    signature_file = f"{OUTPUT_DIR}rsa_{key_size}_signature.bin"

    with open(message_file, 'r') as f:
        message = f.read()

    with open(signature_file, 'rb') as f:
        signature = f.read()

    message_bytes = message.encode('utf-8')
    hash_obj = SHA256.new(message_bytes)

    pkcs1_15.new(public_key).verify(hash_obj, signature)

    end_time = time.time()
    execution_time = end_time - start_time

    print(f"RSA-{key_size} signature verification completed")
    print("Signature is VALID")
    print(f"Execution time: {execution_time:.6f} seconds")

    return execution_time

def sha256_hash(message):
    start_time = time.time()

    message_bytes = message.encode('utf-8')
    hash_obj = SHA256.new(message_bytes)
    hash_hex = hash_obj.hexdigest()

    end_time = time.time()
    execution_time = end_time - start_time

    print("SHA-256 hash generated")
    print(f"Hash: {hash_hex}")
    print(f"Execution time: {execution_time:.6f} seconds")

    return execution_time

def sha256_hash_file(filename):
    start_time = time.time()

    filepath = os.path.join(INPUT_DIR, filename)
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found")
        return None

    hash_obj = SHA256.new()

    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            hash_obj.update(chunk)

    hash_hex = hash_obj.hexdigest()

    end_time = time.time()
    execution_time = end_time - start_time

    print(f"SHA-256 hash of file '{filepath}' generated")
    print(f"Hash: {hash_hex}")
    print(f"Execution time: {execution_time:.6f} seconds")

    return execution_time


def main_menu():
    while True:
        print("\n" + "="*60)
        print("CSE-478 Cryptography Operations Program")
        print("="*60)
        print("1.  AES Encryption (ECB Mode) - Text Input")
        print("2.  AES Encryption (ECB Mode) - File Input")
        print("3.  AES Decryption (ECB Mode) - Text")
        print("4.  AES Decryption (ECB Mode) - File")
        print("5.  AES Encryption (CFB Mode) - Text Input")
        print("6.  AES Encryption (CFB Mode) - File Input")
        print("7.  AES Decryption (CFB Mode) - Text")
        print("8.  AES Decryption (CFB Mode) - File")
        print("9.  RSA Encryption")
        print("10. RSA Decryption")
        print("11. RSA Sign Message - Text")
        print("12. RSA Sign Message - File")
        print("13. RSA Verify Signature - Text")
        print("14. RSA Verify Signature - File")
        print("15. SHA-256 Hash (Text)")
        print("16. SHA-256 Hash (File)")
        print("17. Generate AES Key")
        print("18. Generate RSA Key Pair")
        print("20. Exit")
        print("="*60)

        choice = input("\nEnter your choice (1-20): ")

        if choice == '1':
            plaintext = input("Enter plaintext to encrypt: ")
            key_size = int(input("Enter key size (128 or 256): "))
            aes_encrypt_ecb(plaintext, key_size)

        elif choice == '2':
            filename = input("Enter filename from input/ directory: ")
            key_size = int(input("Enter key size (128 or 256): "))
            aes_encrypt_ecb_file(filename, key_size)

        elif choice == '3':
            key_size = int(input("Enter key size (128 or 256): "))
            aes_decrypt_ecb(key_size)

        elif choice == '4':
            filename = input("Enter encrypted filename from output/ directory: ")
            key_size = int(input("Enter key size (128 or 256): "))
            aes_decrypt_ecb_file(filename, key_size)

        elif choice == '5':
            plaintext = input("Enter plaintext to encrypt: ")
            key_size = int(input("Enter key size (128 or 256): "))
            aes_encrypt_cfb(plaintext, key_size)

        elif choice == '6':
            filename = input("Enter filename from input/ directory: ")
            key_size = int(input("Enter key size (128 or 256): "))
            aes_encrypt_cfb_file(filename, key_size)

        elif choice == '7':
            key_size = int(input("Enter key size (128 or 256): "))
            aes_decrypt_cfb(key_size)

        elif choice == '8':
            filename = input("Enter encrypted filename from output/ directory: ")
            key_size = int(input("Enter key size (128 or 256): "))
            aes_decrypt_cfb_file(filename, key_size)

        elif choice == '9':
            plaintext = input("Enter plaintext to encrypt (max 190 chars for 2048-bit key): ")
            key_size = int(input("Enter key size (1024, 2048, 3072, 4096): "))
            rsa_encrypt(plaintext, key_size)

        elif choice == '10':
            key_size = int(input("Enter key size (1024, 2048, 3072, 4096): "))
            rsa_decrypt(key_size)

        elif choice == '11':
            message = input("Enter message to sign: ")
            key_size = int(input("Enter key size (1024, 2048, 3072, 4096): "))
            rsa_sign(message, key_size)

        elif choice == '12':
            filename = input("Enter filename from input/ directory: ")
            key_size = int(input("Enter key size (1024, 2048, 3072, 4096): "))
            rsa_sign_file(filename, key_size)

        elif choice == '13':
            key_size = int(input("Enter key size (1024, 2048, 3072, 4096): "))
            rsa_verify(key_size)

        elif choice == '14':
            filename = input("Enter original filename from input/ directory: ")
            signature_filename = input("Enter signature filename from output/ directory: ")
            key_size = int(input("Enter key size (1024, 2048, 3072, 4096): "))
            rsa_verify_file(filename, signature_filename, key_size)

        elif choice == '15':
            message = input("Enter text to hash: ")
            sha256_hash(message)

        elif choice == '16':
            filename = input("Enter filename from input/ directory: ")
            sha256_hash_file(filename)

        elif choice == '17':
            key_size = int(input("Enter key size (128, 192, or 256): "))
            generate_aes_key(key_size)

        elif choice == '18':
            key_size = int(input("Enter key size (1024, 2048, 3072, 4096): "))
            generate_rsa_key(key_size)

        elif choice == '19':
            performance_analysis()

        elif choice == '20':
            print("\nExiting program...")
            break

        else:
            print("\nInvalid choice. Please try again.")

if __name__ == "__main__":
    initialize_directories()
    main_menu()
