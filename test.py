import utility_functions.message_cipher as cipher



### test image ciphering 

# file_name = "./Kerberos.png"
# key = '0123456789abcdef0123456789abcdef'
# e = cipher.get_encrypted_img(file_name, key)
# print(e)
# print(cipher.get_decrypted_img(e, key))


### test message ciphering

# test_msg = '''
# The testing message 1
# The testing message 2
# The testing message 3
# The testing message 4
# The testing message 5
# The testing message 6
# The testing message 7
# The testing message 8
# '''
# key = '0123456789abcdef0123456789abcdef'

# ct = cipher.get_encrypt_msg(test_msg,key)
# x = cipher.get_decrypt_msg(ct, key)
# print("original message :", test_msg)
# print("encrypted message:", ct)
# print("decrypted message:", x)