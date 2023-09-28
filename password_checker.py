import hashlib
import os
import smtplib
from email.mime.text import MIMEText
from getpass import getpass
import random
import string

# Directory for storing logs
log_directory = 'logs'

# Create a directory for logs if it doesn't exist
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

# Simulated user data (username, salted_hashed_password)
user_data = {
    'user1': {'salt': 'salt1', 'password_hash': 'hashed_password1'},
    'user2': {'salt': 'salt2', 'password_hash': 'hashed_password2'},
    # Add more users as needed
}

# Password reset requests
password_reset_requests = {}

# Administrator's email address
admin_email = 'admin@example.com'

# Function to generate a random salt
def generate_salt():
    return os.urandom(16).hex()

# Function to hash passwords using SHA-256 with a salt
def hash_password(password, salt):
    salted_password = password + salt
    return hashlib.sha256(salted_password.encode()).hexdigest()

# Function to generate a random password
def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

# Function to decrypt and display a user's password as a string
def display_password_string(username):
    if username in user_data:
        salt = user_data[username]['salt']
        hashed_password = user_data[username]['password_hash']
        return f"Password for user '{username}': {hashed_password}"
    else:
        return f"User '{username}' not found."

# Function to log password changes and send notifications to the administrator
def log_password_change(username, new_password):
    log_file_path = os.path.join(log_directory, 'password_changes.log')
    with open(log_file_path, 'a') as log_file:
        log_file.write(f"User '{username}' changed their password to '{new_password}'\n")
    send_notification(username, new_password)

# Function to send an email notification to the administrator
def send_notification(username, new_password):
    subject = f"Password Change Notification for User '{username}'"
    message = f"User '{username}' has changed their password to '{new_password}'."

    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = admin_email
    msg['To'] = admin_email

    # Replace 'your_smtp_server' and 'your_email_password' with your SMTP server and credentials
    smtp_server = 'your_smtp_server'
    smtp_port = 587
    smtp_username = 'your_email_username'
    smtp_password = 'your_email_password'

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.sendmail(admin_email, admin_email, msg.as_string())
        print(f"Notification sent to administrator at {admin_email}")
    except Exception as e:
        print(f"Failed to send notification: {str(e)}")

# Function to update a user's password
def update_password(username, new_password):
    if username in user_data:
        old_password_hash = user_data[username]['password_hash']
        if old_password_hash != new_password:
            user_data[username]['password_hash'] = new_password
            log_password_change(username, new_password)
            print(f"Password for user '{username}' updated successfully.")
        else:
            print(f"New password is the same as the old password for user '{username}'.")
    else:
        print(f"User '{username}' not found.")

# Function to add a new user with a secure password
def add_user(username, password):
    if username not in user_data:
        salt = generate_salt()
        hashed_password = hash_password(password, salt)
        user_data[username] = {'salt': salt, 'password_hash': hashed_password}
        print(f"User '{username}' added successfully.")
    else:
        print(f"User '{username}' already exists. Choose a different username.")

# Function to display a user's password (hashed)
def display_password(username):
    password_string = display_password_string(username)
    print(password_string)

# Function to request a password reset
def request_password_reset(username):
    if username in user_data:
        reset_code = ''.join(random.choices(string.digits, k=6))
        password_reset_requests[username] = reset_code
        print(f"Password reset code sent to the registered email of user '{username}'.")
        send_password_reset_email(username, reset_code)
    else:
        print(f"User '{username}' not found.")

# Function to send a password reset email
def send_password_reset_email(username, reset_code):
    subject = f"Password Reset Request for User '{username}'"
    message = f"Dear '{username}',\n\n" \
              f"You have requested to reset your password. Please use the following code to reset your password:\n" \
              f"Reset Code: {reset_code}\n\n" \
              f"If you did not request this, please ignore this email.\n\n" \
              f"Best regards,\n" \
              f"Your Admin"

    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = admin_email
    msg['To'] = admin_email

    # Replace 'your_smtp_server' and 'your_email_password' with your SMTP server and credentials
    smtp_server = 'your_smtp_server'
    smtp_port = 587
    smtp_username = 'your_email_username'
    smtp_password = 'your_email_password'

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.sendmail(admin_email, admin_email, msg.as_string())
        print(f"Password reset email sent to '{username}' at their registered email address.")
    except Exception as e:
        print(f"Failed to send password reset email: {str(e)}")

# Function to reset a user's password
def reset_password(username, reset_code):
    if username in user_data and username in password_reset_requests:
        if password_reset_requests[username] == reset_code:
            new_password = generate_random_password()
            salt = generate_salt()
            hashed_password = hash_password(new_password, salt)
            user_data[username]['salt'] = salt
            user_data[username]['password_hash'] = hashed_password
            log_password_change(username, hashed_password)
            print(f"Password for user '{username}' reset successfully. New password: {new_password}")
        else:
            print("Invalid reset code. Please request a new reset code.")
    else:
        print(f"Invalid user or reset code. Please request a new reset code.")

# Function to display logs of password changes
def display_logs():
    log_file_path = os.path.join(log_directory, 'password_changes.log')
    try:
        with open(log_file_path, 'r') as log_file:
            logs = log_file.read()
            print("Password Change Logs:")
            print(logs)
    except FileNotFoundError:
        print("No password change logs found.")

# Main menu function
def main_menu():
    while True:
        print("\nOptions:")
        print("1. Update Password")
        print("2. Add New User")
        print("3. Display User Password (Hashed)")
        print("4. Display Password Change Logs")
        print("5. Display Password as String")
        print("6. Request Password Reset")
        print("7. Reset Password")
        print("8. Exit")

        choice = input("Enter your choice (1/2/3/4/5/6/7/8): ")

        if choice == '1':
            username = input("Enter username: ")
            new_password = getpass("Enter new password: ")
            salt = user_data[username]['salt']
            hashed_password = hash_password(new_password, salt)
            update_password(username, hashed_password)
        elif choice == '2':
            username = input("Enter new username: ")
            password = getpass("Enter password for the new user: ")
            add_user(username, password)
        elif choice == '3':
            username = input("Enter username: ")
            display_password(username)
        elif choice == '4':
            display_logs()
        elif choice == '5':
            username = input("Enter username: ")
            password_string = display_password_string(username)
            print(password_string)
        elif choice == '6':
            username = input("Enter username for password reset request: ")
            request_password_reset(username)
        elif choice == '7':
            username = input("Enter username for password reset: ")
            reset_code = input("Enter reset code sent to your email: ")
            reset_password(username, reset_code)
        elif choice == '8':
            break
        else:
            print("Invalid choice. Please select a valid option.")

# Example usage:
if __name__ == "__main__":
    main_menu()
