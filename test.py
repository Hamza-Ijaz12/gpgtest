import gnupg

gpg = gnupg.GPG()
print(gpg.list_keys(secret=True))

def import_secret_key(gpg, key_path):
    
    import_result = gpg.import_keys_file(key_path)
    if import_result:
        print("Key imported successfully. Key count:", len(import_result.fingerprints))
    else:
        print("Failed to import key.")



# Path to your public and private keyring (if not default)
# gpg = gnupg.GPG(gnupghome='/path/to/your/keyring')

def encrypt_message(public_key_path, message):
    # Import public key
    with open(public_key_path, 'rb') as f:
        key_data = f.read()
    import_result = gpg.import_keys(key_data)
    
    if not import_result:
        return "Error importing public key"
    
    fingerprint = import_result.fingerprints[0]
    
    # Encrypt the message
    encrypted_data = gpg.encrypt(message, fingerprint, always_trust=True)
    if encrypted_data.ok:
        return str(encrypted_data)
    else:
        return f"Error encrypting message: {encrypted_data.status}"

def decrypt_message(encrypted_message, passphrase):
    # Decrypt the message
    decrypted_data = gpg.decrypt(encrypted_message, passphrase=passphrase)
    if decrypted_data.ok:
        return str(decrypted_data)
    else:
        return f"Decryption failed: {decrypted_data.status}, {decrypted_data.stderr}"

# Paths to your public and private keys
public_key_path = '1.asc'
private_key_path = '2p.asc' # Note: This is not used directly in code but assumed to be in your keyring

# Your passphrase for the private key
passphrase = 'mykey'

# The message you want to encrypt
message = 'Hello, GPG!'

import_secret_key(gpg,'2p.asc')
# Encrypt the message
encrypted_message = encrypt_message(public_key_path, message)
print("Encrypted Message:\n", encrypted_message)

# Decrypt the message
# Make sure the private key corresponding to the public key is imported to your keyring
decrypted_message = decrypt_message(encrypted_message, passphrase)
print("Decrypted Message:\n", decrypted_message)









