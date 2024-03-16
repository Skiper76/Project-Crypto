#S1 app.py
import bcrypt
import getpass
import requests  

user_database = {}

def encrypt_password(hashed_password):
    response = requests.post('https://hsm:8081/encrypt', json={'data': hashed_password.hex()}, verify=False)  # 'verify=True' active la vérification SSL.
    return bytes.fromhex(response.json()['encrypted'])

def decrypt_password(encrypted_hashed_password):
    response = requests.post('https://hsm:8081/decrypt', json={'data': encrypted_hashed_password.hex()}, verify=False)  # 'verify=True' pour la vérification SSL.
    return bytes.fromhex(response.json()['decrypted'])

def register_user():
    username = input("Enter your username for registration: ")
    if username in user_database:
        print("Username already exists. Please try a different username.")
        return
    password = getpass.getpass("Enter your password for registration: ")
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    encrypted_hashed_password = encrypt_password(hashed_password)
    user_database[username] = encrypted_hashed_password
    print("Registration successful!")

def login_user():
    username = input("Enter your username for login: ")
    if username not in user_database:
        print("Username does not exist. Please register first.")
        return
    password = getpass.getpass("Enter your password for login: ")
    encrypted_hashed_password = user_database[username]
    hashed_password = decrypt_password(encrypted_hashed_password)
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
