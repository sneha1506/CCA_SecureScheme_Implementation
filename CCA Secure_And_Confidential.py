#!/usr/bin/env python

import hashlib,random
from Crypto.Cipher import AES
from hashlib import sha1
from hmac import *
import time

"""This method geneerates two keys form a single symmetric key. 
 One key is used to represent the Encryption key and the other
 key is used to authenticate """
def generate_keys():
    Symmetric_key = "My key"
    public_constantA = "Constant1"
    public_constantB = "Constant2"
    h = hashlib.sha1()
    h.update(Symmetric_key+" "+public_constantA)
    Authentication_Key = h.hexdigest()
    h.update(Symmetric_key+" "+public_constantB)
    Encryption_Key = h.hexdigest()
    return Authentication_Key,Encryption_Key

# This method converts given key to 32-byte key
def ConvertKey_to_32_byte(key):
    Converted_key = hashlib.sha256(key).digest()
    return Converted_key;

# This method encrypts the file using AES encryption in CBC mode
def Encryption():
    obj = AES.new(ConvertKey_to_32_byte(Encryption_Key), AES.MODE_CBC, iv)
    ciphertext = obj.encrypt(Message_padding(message))
    return ciphertext

# The verification algorithm computes the MAC codde using Authentication key
def Verification():
    from hashlib import sha256
    import hmac
    # Calling the generate_keys method to get the key for authentication
    Authentication_Key,Encryption_Key = generate_keys()
    # The Base String or the message for which the hash is to be created 
    Message = Encryption()

    """Calculate the tag using hmac. the new method of hmac takes three arguments
    the key, message and the diges mode in this case it is sha1"""

    HashTag = hmac.new(Authentication_Key, msg=Message, digestmod=sha256)
    # returning the calculated tag value
    return HashTag.digest().encode("base64").rstrip('\n')

def Decryption():
    """Decryption method takes the encrypted cipher and 
    the tag and calculates the plaintext 
    """
    plaintext = str()
    try:
        Authentication_Key,Encryption_Key = generate_keys()
        Verf_tag1 = Verification()
        Verf_tag2 = Generate_HMAC()
        
        if(str(Verf_tag1)==str(Verf_tag2)):
            print("MAC tags are verified")
            obj2 = AES.new(ConvertKey_to_32_byte(Encryption_Key), AES.MODE_CBC, iv)
            plaintext = obj2.decrypt(ciphertext)
    except Exception as e:
        raise("Exception raised at Decryption() : {}".format(e))

    return plaintext

def Generate_HMAC():
    from hashlib import sha256
    import hmac

    # Calling the generate_keys method to get the key for authentication
    Authentication_Key,Encryption_Key = generate_keys()
      
    # The Base String or the message for which the hash is to be created 
    Message = Encryption()

    """Calculate the tag using hmac. the new method of hmac takes three arguments
    the key, message and the diges mode in this case it is sha1 """
    HashTag = hmac.new(Authentication_Key, msg=Message, digestmod=sha256)

    # returning the calculated tag value
    return HashTag.digest().encode("base64").rstrip('\n')


# This method converts the message or input strings to a multiple of 16 in length
def Message_padding(message):
    Message_length = len(message)
    # print Message_length
    remainder = Message_length%16
    if (remainder) !=0:
        Padding_length = 16-remainder
        message = message+" "*Padding_length
    # print Padding_length
    return message

if __name__ == '__main__':
    in_file = 'in.txt'
    en_file = 'Encrypted.txt'
    de_file = 'Decrypted.txt'
    
    in_FH = open(in_file,'r')
    encrypt_FH = open(en_file, 'w')
    decrypt_FH = open(de_file, 'w')
    
    message = in_FH.read()

    Authentication_Key,Encryption_Key = generate_keys()
    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    
    print ("Encryption started:")
    encrypt_start = time.time()
    
    ciphertext = Encryption()
    
    print("Encryption Time taken {} seconds".format(time.time()-encrypt_start))
    encrypt_FH.write(ciphertext)

    MAC_Tag = Generate_HMAC()
    print ("MAC generation started:\n"+"MAC Tag= "+Generate_HMAC())
    encrypt_FH.write(MAC_Tag)
    encrypt_FH.write(iv)
    
    print("Decryption Started:")
    decrypt_start = time.time()
    
    plaintext = Decryption()
    print("Decryption Time taken {} seconds".format(time.time()-decrypt_start))
    decrypt_FH.write(plaintext)
    
    print("Total Time taken for the CCA secure and confidential algorithm to run is {} seconds".format(time.time()-encrypt_start))
    decrypt_FH.close()
    encrypt_FH.close()
    in_FH.close()
