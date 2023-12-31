import hashlib
import os

# Example input string (replace this with the actual input string)
input_string = 'your_input_string_here'

# Generate a secure random salt
salt = os.urandom(16)

# Specify the number of iterations and the desired key length (32 bytes)
iterations = 100000
key_length = 32

# Derive the key using PBKDF2
derived_key = hashlib.pbkdf2_hmac('sha256', input_string.encode(), salt, iterations, dklen=key_length)

# Converting the derived key to a hex representation for readability
hex_key = derived_key.hex()
print(f"(key: {hex_key}, length: {len(derived_key)})")