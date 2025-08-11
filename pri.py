import bcrypt

passwords = {
    "admin1": "adminpassword",
    "staff1": "staffpassword"
}

for username, plain_password in passwords.items():
    hashed = bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt())
    print(f'"username": "{username}", "password": "{hashed.decode()}"')
