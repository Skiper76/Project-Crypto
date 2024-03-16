import bcrypt
import getpass
import requests
import json
import os
import ssl

# Paramètres de configuration
USER_DATABASE_FILE = 'user_database.json'
SALT_ROUNDS = 12

# Charger ou initialiser la base de données utilisateur
if os.path.exists(USER_DATABASE_FILE):
    with open(USER_DATABASE_FILE, 'r') as file:
        user_database = json.load(file)
else:
    user_database = {}

def save_user_database():
    with open(USER_DATABASE_FILE, 'w') as file:
        json.dump(user_database, file)

def encrypt_password(hashed_password):
    response = requests.post('https://hsm:8081/encrypt', json={'data': hashed_password.hex()}, verify="cert.pem")
    return bytes.fromhex(response.json()['encrypted'])

def decrypt_password(encrypted_hashed_password):
    response = requests.post('https://hsm:8081/decrypt', json={'data': encrypted_hashed_password.hex()}, verify="cert.pem")
    return bytes.fromhex(response.json()['decrypted'])

def calculate_entropy(password):
    charset_size = (
        (26 if any(c.islower() for c in password) else 0) + 
        (26 if any(c.isupper() for c in password) else 0) + 
        (10 if any(c.isdigit() for c in password) else 0) + 
        (32 if any(c in '!@#$%^&*()-_+=' for c in password) else 0)
    )
    entropy = len(password) * charset_size.bit_length()
    return entropy

def evaluate_password_strength(password):
    entropy = calculate_entropy(password)
    if entropy < 64:
        return 'faible'
    elif entropy < 80:
        return 'correct'
    elif entropy < 100:
        return 'sûr'
    else:
        return 'très sûr'

def register_user():
    username = input("Enter your username for registration: ")
    if username in user_database:
        print("Username already exists. Please try a different username.")
        return
    password = getpass.getpass("Enter your password for registration: ")
    strength = evaluate_password_strength(password)
    print(f"Strength of your password: {strength}.")
    if strength == 'faible':
        print("Password is too weak. Please use a stronger password.")
        return
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(SALT_ROUNDS))
    encrypted_hashed_password = encrypt_password(hashed_password)
    user_database[username] = encrypted_hashed_password.hex()
    save_user_database()
    print("Registration successful!")

def login_user():
    username = input("Enter your username for login: ")
    if username not in user_database:
        print("Username does not exist. Please register first.")
        return
    password = getpass.getpass("Enter your password for login: ")
    encrypted_hashed_password = user_database[username]
    hashed_password = decrypt_password(bytes.fromhex(encrypted_hashed_password))
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
            break
        else:
            print("Invalid choice. Please try again.")
    save_user_database()

if __name__ == "__main__":
    main()
