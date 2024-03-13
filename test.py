#Cette app est une combinaison des 2 services dans une app pour test.
import bcrypt
import getpass
import tink
from tink import aead

# Initialisation de Google Tink
def init_tink():
    aead.register()
    keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM)
    return keyset_handle

# Fonction pour chiffrer les données
def encrypt_data(keyset_handle, data):
    aead_primitive = keyset_handle.primitive(aead.Aead)
    ciphertext = aead_primitive.encrypt(data, b'')  # Pas de contexte d'authentification nécessaire ici
    return ciphertext

# Fonction pour déchiffrer les données
def decrypt_data(keyset_handle, ciphertext):
    aead_primitive = keyset_handle.primitive(aead.Aead)
    plaintext = aead_primitive.decrypt(ciphertext, b'')  # Assurez-vous que le contexte d'authentification correspond
    return plaintext

# Modification du stockage et de la vérification des mots de passe
user_database = {}
keyset_handle = init_tink()

def register_user():
    username = input("Enter your username for registration: ")
    if username in user_database:
        print("Username already exists. Please try a different username.")
        return
    password = getpass.getpass("Enter your password for registration: ")
    print("votre pwd :", password)
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()) # Hashage du mot de passe + salage
    print("votre hash:", hashed_password)
    encrypted_hashed_password = encrypt_data(keyset_handle, hashed_password)  # Chiffrement du hash
    print("votre encryption :", encrypted_hashed_password)
    
    user_database[username] = encrypted_hashed_password
    print("Registration successful!")

def login_user():
    username = input("Enter your username for login: ")
    if username not in user_database:
        print("Username does not exist. Please register first.")
        return
    password = getpass.getpass("Enter your password for login: ")
    print("votre pwd:", password)   
    encrypted_hashed_password = user_database[username]
    print("votre encrypted hash:", encrypted_hashed_password)
    hashed_password = decrypt_data(keyset_handle, encrypted_hashed_password)  # Déchiffrement du hash
    print("votre hash", hashed_password)
    
    if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
        print("Login successful!")
    else:
        print("Incorrect password. Please try again.")

def main():
    while True:
        print("1. Register")
        print("2. Login")
        print("3. Quit")
        choice = input("Choose an option: ")
        if choice == "1":
            register_user()
        elif choice == "2":
            login_user()
        elif choice == "3":
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

