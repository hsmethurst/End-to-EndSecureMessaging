'''
The message encryption follows Advanced Encryption Standard(AES) and is designed for 256-bit key.
The  Electronic Code Book (ECB) is used to implement as cipher implementation mode.
'''

from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

'''
it receives any size of msg and 32 bytes key(accept str, byte types)
it returns cipher text and iv as str object
'''
def get_encrypt_msg(msg, key):
  try:
    msg = msg.encode('utf8')
  except(UnicodeDecodeError, AttributeError):
    pass
  try:
    key = key.encode('utf8')
  except(UnicodeDecodeError, AttributeError):
    pass
  
  cipher = AES.new(key, AES.MODE_ECB)
  ct_bytes = cipher.encrypt(pad(msg, AES.block_size))
  ct = b64encode(ct_bytes).decode('utf8')
  return ct

'''
it receives any size of msg and 32 bytes key(accept str, byte types)
it returns plain text as str object
'''
def get_decrypt_msg(msg, key):
  try:
    msg = b64decode(msg)
  except(UnicodeDecodeError, AttributeError):
    pass
  try:
    key = key.encode('utf8')
  except(UnicodeDecodeError, AttributeError):
    pass
  #msg = b64decode(msg)
  cipher = AES.new(key, AES.MODE_ECB)
  plain_text = unpad(cipher.decrypt(msg), AES.block_size)
  return plain_text.decode('utf8')

'''
function to encrypt the image
it receives the file_path and shared key
it returns the encrypted image binary file
'''
def get_encrypted_img(file_path, key):
  try:
    f = open(file_path, 'rb')
  # if file is not found, then raise error and return None  
  except FileNotFoundError as e:
    print("file %s is not found" % file_path)
    return None
  else:
    img = f.read()
    encrypted_img = encrypt_img(img, key)
    f.close()
    return encrypted_img


'''
function to decrypt the image
it receive binary encrypted image file and shared key
'''
def get_decrypted_img(encrypted_img, key):

  # download folder for client sides
  folder = "./downloads/"
  file_name = input("Enter file name: ")
  dest = folder + file_name

  f = open(dest, 'wb')
  plain_img = decrypt_img(encrypted_img, key)

  f.write(plain_img)
  f.close()


'''
function to encrypt the img
it receives binary image file and shared key
it returns binary encrypted image file
'''
def encrypt_img(img, key):

  try:
    key = key.encode('utf8')
  except(UnicodeDecodeError, AttributeError):
    pass

  # ECB should not be used for iamge encrytion
  # it should be mentioned during the demo
  cipher = AES.new(key, AES.MODE_ECB)
  ci_bytes = cipher.encrypt(pad(img, AES.block_size))

  return ci_bytes

'''
function to decrypt the image
it receives encrypted file and key
it returns plain binary image file
'''
def decrypt_img(encrypted_img, key):

  try:
    encrypted_img = encrypted_img.encode('utf8')
  except(UnicodeDecodeError, AttributeError):
    pass

  try:
    key = key.encode('utf8')
  except(UnicodeDecodeError, AttributeError):
    pass
  
  try:
    cipher = AES.new(key, AES.MODE_ECB)
    plain_img = unpad(cipher.decrypt(encrypted_img), AES.block_size)

    return plain_img

  except (ValueError, KeyError):    
    print("Incorrect inputs")
