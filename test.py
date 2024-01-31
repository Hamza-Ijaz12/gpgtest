# utils.py
import gnupg
gpg = gnupg.GPG()
def encrypt_message(public_key_path, message):
    public_key = gpg.import_keys_file(public_key_path)
    if not public_key.results or 'fingerprint' not in public_key.results[0]:
        return "Error importing public key"

    fingerprint = public_key.results[0]['fingerprint']
    
    # Encrypt the message 
    encrypted_data = gpg.encrypt(message, fingerprint,always_trust=True)
    if encrypted_data.ok:
        return str(encrypted_data)
    else:
        print('Encrypted message:', encrypted_data.status)
        return str(encrypted_data.status)


def decrypt_message( encrypted_message, passphrase,privatekey):
    private_key = gpg.import_keys_file(privatekey)
    if not private_key.results or 'fingerprint' not in private_key.results[0]:
        return "Error importing public key"

    fingerprint = private_key.results[0]['fingerprint']
    decrypted_data = gpg.decrypt(encrypted_message, passphrase=passphrase)
    if decrypted_data.ok:
        return str(decrypted_data)
    else:
        print('Encrypted message:', decrypted_data.status)
        print('Decryption failed:', decrypted_data.status)
        print('Error message:', decrypted_data.stderr)
        decrypted_data=False
        return decrypted_data
    
en_message = encrypt_message('1.asc',"Hello world")
print(en_message)
print(decrypt_message(en_message,'mykey','2p.asc'))