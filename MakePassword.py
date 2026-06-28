import bcrypt
password = "YourSecretPasswordHere!"
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
print("=== Hash ===")
print(hashed.decode())
print("==================================")
