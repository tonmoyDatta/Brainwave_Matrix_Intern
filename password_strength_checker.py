import re
import math

# List of common passwords -->
common_passwords = [
    "123456", "password", "123456789", "12345678", "12345", "1234567", "123123", "1234567890",
    "qwerty", "abc123", "password1", "admin", "letmein", "welcome", "monkey", "iloveyou",
    "1234", "sunshine", "princess", "football", "111111", "123", "dragon", "master",
    "qwertyuiop", "login", "passw0rd", "starwars", "baseball", "654321", "superman",
    "asdfghjkl", "qazwsx", "trustno1", "121212", "batman", "123qwe", "zaq12wsx", "freedom",
    "love", "whatever", "987654321", "666666", "hello123", "hunter", "qazxsw", "secret",
    "killer", "google", "welcome1", "jesus", "mustang", "access", "michael", "soccer",
    "tigger", "chocolate", "asdfgh", "shadow", "buster", "ginger", "charlie", "aa123456",
    "maggie", "jennifer", "michelle", "123abc", "football1", "jordan", "michelle1", "trustme",
    "iloveyou1", "pass123", "hockey", "asdf1234", "888888", "summer", "computer", "ashley",
    "batman1", "harley", "internet", "admin123", "iloveyou2", "loveme", "soccer1", "thomas",
    "happy123", "admin1", "newyork", "welcome123", "cowboy", "abcdef", "william", "123123123",
    "q1w2e3r4", "cheese", "purple", "qaz123", "love123"
]


# Custom blacklist words for additional security -->
blacklist_words = [
    "myname", "username", "firstname", "lastname", "birthdate", "hometown", "favorite",
    "petname", "1234abcd", "qwerty123", "companyname", "password123", "2023password",
    "qwertyui", "rootadmin", "superuser", "guestlogin", "default123", "welcome2023",
    "iloveyou123", "letmein123", "baseball123", "footballfan", "winter2024", "springtime",
    "summerfun", "autumnfall", "january01", "february14", "aprilfool", "july4th",
    "november11", "december25", "secretpass", "changeme123", "newpassword", "111222333",
    "abcdef123", "tempuser", "toorpassword", "adminroot", "samplepass", "backup123",
    "masterkey", "strongpass", "weakpass", "lockitup", "nocomment", "fakepass",
    "simplename", "databasename", "developer123", "codename", "blank1234", "tempaccess",
    "webaccess", "secureme", "trusteduser", "luckyday", "sunshine24", "starsky",
    "hunter45", "keeper12", "fortune99", "badpassword", "notsecure", "easyguess",
    "defaultpwd", "encryptme", "mobilepass", "homepass", "office2023", "android123",
    "iosdevice", "samsung123", "iphone123", "windows11", "linuxroot", "securekey",
    "onetwothree", "repeatme", "mystreet", "bankpin", "alphabeta", "important",
    "priority1", "unlockme", "mysafeplace", "birthday21", "specialword", "phrase123",
    "lastyear", "summer2023", "personal01", "dontshare", "noaccess", "unrestricted",
    "myfavorite", "datatoken", "verifyme"
]


# Patterns commonly seen on keyboards -->
keyboard_patterns = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm", "123456", "12345678",
    "123456789", "1234567890", "1q2w3e4r", "1qaz2wsx", "qwert123", "qazwsx", "0987654321",
    "mnbvcxz", "987654321", "1q2w3e", "1q2w3e4r5t", "qweasd", "wsxcde", "123qwe", "123qweasd",
    "qwe123", "qwer1234", "asdf1234", "1234qwer", "12qwaszx", "q1w2e3r4t5", "09876",
    "zxcv1234", "1a2s3d4f", "poiuytrewq", "lkjhgfds", "poi098", "3edc4rfv", "q1w2e3r4",
    "qaz123", "123edc", "1zaq2wsx", "asdfqwer", "qazplm", "13579", "abcdef", "ghijkl",
    "lkjhgfdsa", "9876poi", "poiuy", "qwert1", "wertyui"
]



def calculate_entropy(password):
    """Estimate password entropy based on character diversity and length."""
    # Character pools based on character types
    unique_characters = set(password)
    pool_size = len(unique_characters)  # Number of unique characters in the password

    # Calculate entropy
    if pool_size > 1:
        entropy = len(password) * math.log2(pool_size)
    else:
        entropy = 0  # If all characters are the same, entropy should be very low
    return entropy



def check_sequential_characters(password):
    """Check for sequential characters in the password."""
    for i in range(len(password) - 2):
        # Check for increasing sequences -->
        if ord(password[i]) + 1 == ord(password[i+1]) and ord(password[i]) + 2 == ord(password[i+2]):
            return True
        # Check for decreasing sequences -->
        if ord(password[i]) - 1 == ord(password[i+1]) and ord(password[i]) - 2 == ord(password[i+2]):
            return True
    return False




def check_repeated_characters(password):
    """Check if the password contains repeated characters."""
    for char in set(password):
        if password.count(char) > len(password) // 2:
            return True
    return False




def check_password_strength(password):
    min_length = 8
    score = 0
    feedback = []

    # Check length
    if len(password) < min_length:
        feedback.append("Weak: Password must be at least 8 characters long.")
    else:
        score += len(password) - min_length

    # Character diversity checks
    if re.search(r'[a-z]', password):
        score += 2
    if re.search(r'[A-Z]', password):
        score += 3
    if re.search(r'[0-9]', password):
        score += 3
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 5

    # Common password check
    if password in common_passwords:
        return "Very Weak: This password is too common. Please choose a more unique one."

    # Blacklist words check
    if any(word in password.lower() for word in blacklist_words):
        feedback.append("Weak: Password contains common or blacklisted words. Avoid using easily guessable words.")

    # Keyboard pattern check
    if any(pattern in password.lower() for pattern in keyboard_patterns):
        feedback.append("Weak: Avoid using keyboard patterns like 'qwerty' or '1234'.")

    # Sequential character check
    if check_sequential_characters(password):
        feedback.append("Weak: Password contains sequential characters. Consider mixing it up.")

    # Repeated character check
    if check_repeated_characters(password):
        feedback.append("Weak: Password contains too many repeated characters.")

    # Entropy calculation for more detailed analysis
    entropy = calculate_entropy(password)
    if entropy < 28:
        feedback.append("Weak: The password's entropy is too low for entropy < 28. Consider using a mix of different character types.")
    elif 28 <= entropy < 36:
        feedback.append("Medium: The password could be stronger with more diverse characters including 28 <= entropy < 36.")
    elif 36 <= entropy < 60:
        feedback.append("Strong: The password is relatively strong including 36 <= entropy < 60.")
    else:
        feedback.append("Very Strong: The password has high entropy > 60 and good character diversity.")

    # Provide feedback and final score
    feedback.append(f"Password entropy: {entropy:.2f} bits.")
    feedback.append(f"Overall score: {score}/20.")

    return " | ".join(feedback)

# User input
password = input("Enter your password: ")
strength_feedback = check_password_strength(password)
print("Password Strength Feedback:", strength_feedback)
