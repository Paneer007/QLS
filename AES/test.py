from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

test = b"hello world"
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC)
ct_bytes = cipher.encrypt(pad(test, AES.block_size))
ct = b64encode(ct_bytes).decode('utf-8')
iv = b64encode(cipher.iv).decode('utf-8')

print(ct)
print(iv)
print(key)

try:
    cipher = AES.new(key, AES.MODE_CBC, b64decode(iv))
    pt = unpad(cipher.decrypt(b64decode(ct)), AES.block_size)
    print("The message was: ", pt.decode('utf-8'))
    
except Exception as e:
    print(str(e))
