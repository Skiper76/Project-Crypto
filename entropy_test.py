import math
import getpass

# Function to calculate password entropy
def calculate_entropy(password):
    # Define the character sets
    lowercase = set('abcdefghijklmnopqrstuvwxyz')
    uppercase = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    digits = set('0123456789')
    special_characters = set('!@#$%^&*()-_+=')
    all_characters = lowercase.union(uppercase, digits, special_characters)
    
    # Calculate the number of possible symbols
    N = sum([
        (26 if any(c in lowercase for c in password) else 0),
        (26 if any(c in uppercase for c in password) else 0),
        (10 if any(c in digits for c in password) else 0),
        (len(special_characters) if any(c in special_characters for c in password) else 0)
    ])
    
    L = len(password)
    # Calculate the entropy
    H = L * (math.log(N) / math.log(2))
    return H

def is_password_strong(password):
    entropy = calculate_entropy(password)
    print(f"Password entropy: {entropy:.2f} bits")
    MIN_ENTROPY = 64  # Define the minimum entropy value for a strong password (64 or 80 is good)
    if entropy >= MIN_ENTROPY:
        print("This password is strong.")
        return True
    else:
        print("This password is not strong enough.")
        return False

def main():
    print("Password Strength Checker")
    while True:
        # User interface to enter the password
        password = getpass.getpass("Enter a password to check its strength: ")
        # Check the password strength
        if is_password_strong(password):
            break  # If the password is strong, exit the loop
        else:
            print("Please try again with a more complex password.")

if __name__ == "__main__":
    main()
