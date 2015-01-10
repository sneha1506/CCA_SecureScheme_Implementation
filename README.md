# CCA_SecureScheme_Implementation
CCA Security

Usage:-

The file CCA Secure_And_Confidential code encrypts the bible text(stored as in.txt) using AES_CBC mode of encryption and a MAC tag is calculated for the encrypted message using HMAC and then the (Cipher, Tag) is sent for the decryption process.

At the Decryption process, a tag is calculated for the received cipher and the tag is verified with the received tag. If both the tags match then the decryption process is started. 

The code “CCA Secure_And_Confidential” uses the inbuilt AES encryption from “PyCrypto” library. It also uses the hash function “SHA256” in order to calculate the HMAC tag.


Modules needed:-

The code CCA Secure_And_Confidential encryption needs PyCrypto module to install it you can use the following commands in your terminal or command prompt

	sudo install pip (Command to install pip)
	pip install PyCrypto (Command to install Pycrypto)


How to run the file:-

Run the file using the command “python CCA Secure_And_Confidential.py” and it creates two files Encrypted.txt and Decryption.txt in your current working directory 

I have also included the encrypted and decrypted files in the code folder
