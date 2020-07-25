#Zhihao Pan
#Server
import sys
from Server_functions import integrity_check, find_public_key, find_private_key, encrypt, decrypt
import socket
import json
import base64
import time
import os
serversocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ip = "10.0.0.7"
port = 9999
serversocket.bind((ip, port))

#Calculating the n,e,and d
p = int(input('Please input prime number for p:'))
q = int(input('Please input prime number for q:'))
n = p*q
e = find_public_key(p,q)
print('Found public key e:',e)
d = find_private_key(p,q,e)
print('Found private key d:',d)

#receiving the public key
client_public_key, addr = serversocket.recvfrom(1024) #receiving the client's public key
client_public_key = int(client_public_key.decode())
client_public_key_n, addr = serversocket.recvfrom(1024) #receiving the client's n
client_public_key_n = int(client_public_key_n.decode())

print("\nRecieved the Client's public key:",client_public_key)

#sending the public key
print("\nSending Server's public key...")
e = str(e)
sent = serversocket.sendto(e.encode(), addr)
n = str(n)
sent = serversocket.sendto(n.encode(), addr)
n = int(n)

print("\nWaiting to receive message on port " + str(port) + '\n')

#Waiting for Client's upload request
request_msg, addr = serversocket.recvfrom(1024)
print("Client's upload request message:"+request_msg.decode())

#Reply to Client's request
response_msg = str(input('\nPlease enter the response(yes or no):'))
sent = serversocket.sendto(response_msg.encode(), addr)

#if yes, then start uploading
if response_msg.lower() == 'yes':

    print("\nWaiting to receive file on port " + str(port))

    #Recieving the file name from the Client
    filename, addr = serversocket.recvfrom(1024)
    filename = filename.decode()
    
    key_of_dict = 1

    #Check if file exit
    #If it exit, then deleted the old one
    if os.path.exists(filename):
        os.remove(filename)
    
    #Creating the file with the filename and appending data into it
    with open(filename,'a+b') as data:
        
        #Receiving code for pdf, png, and jpg
        if filename[-3::] == 'pdf' or filename[-3::] == 'png' or filename[-3::] == 'jpg':

            #Recieving from the Client
            byte_file, addr = serversocket.recvfrom(124928) #124928Bytes
            str_file = byte_file.decode('UTF-8')  #convert to string
            str_file_d = json.loads(str_file)  #string to dict with key
            list_file = str_file_d.get(str(key_of_dict))   #change the value of the key (the string) into list of integer

            #Decrypt it using Server's own private key
            recover_file = decrypt(list_file,d,n)

            #Receive the hash value
            hash_value, addr = serversocket.recvfrom(124928)
            print('\nIntegrity Check \nHash value of the file:')
            int_check = integrity_check(byte_file)  #Calculate the hash value
            print(int_check)  #print the hash value to check with the Client Side

            #Check if the hash value is equal to the calculation
            if int_check == hash_value.decode():
                
                #if they are the same, then write into the file
                recover_file = recover_file.encode('UTF-8')
                data.write(base64.decodebytes(recover_file))  #change to bytes and write to the file
                
            else:  #if not the same, then print out someone had modified it
                print('Someone had modified it in the transit!')
                
            while (sys.getsizeof(list_file)!=28):  #this will end when it reach to the end size
                
                key_of_dict = int(key_of_dict)
                key_of_dict = str(key_of_dict + 1)  #increasing the key of the dict
                byte_file, addr = serversocket.recvfrom(124928)  #Receiving the file
                str_file = byte_file.decode('UTF-8')  #convert to string
                str_file_d = json.loads(str_file)  #string to dict with key
                list_file = str_file_d.get(key_of_dict)   #change the value of the key (the string) into list of integer

                # Decrypt it using Server's own private key
                recover_file = decrypt(list_file,d,n)

                # Receive the hash value
                hash_value, addr = serversocket.recvfrom(124928)
                int_check = integrity_check(byte_file)  #Calculate the hash value
                print(int_check)  #print the hash value to check with the Client Side
                
                # Check if the hash value is equal to the calculation
                if int_check == hash_value.decode():
                    
                    # if they are the same, then write into the file
                    recover_file = recover_file.encode('UTF-8')
                    data.write(base64.decodebytes(recover_file))
                    
                else:  #if not the same, then print out someone had modified it
                    print('Someone had modified it in the transit!')
                    
        # if the file is not pdf, png, and jpg, then use this for other type of file
        else:
            str_file, addr = serversocket.recvfrom(124928)
            str_file_d = json.loads(str_file.decode())  #string to dict with key
            list_file = str_file_d.get(str(key_of_dict))   #change the value of the key (the string) into list of integer

            # Decrypt it using Server's own private key
            recover_file = decrypt(list_file, d, n)

            # Receive the hash value
            hash_value, addr = serversocket.recvfrom(124928)
            print('\nIntegrity Check \nHash value of the file:')
            int_check = integrity_check(str_file)    #Calculate the hash value
            print(int_check)  #print the hash value to check with the Client Side
            
            # Check if the hash value is equal to the calculation
            if int_check == hash_value.decode():
                
                # if they are the same, then write into the file
                data.write(recover_file.encode())
                
            else:  #if not the same, then print out someone had modified it
                print('Someone had modified it in the transit!')
                
            while (sys.getsizeof(list_file) != 28):  #this will end when it reach to the end size
                key_of_dict = int(key_of_dict)
                key_of_dict = str(key_of_dict + 1)
                str_file, addr = serversocket.recvfrom(124928)
                str_file_d = json.loads(str_file.decode())  #string to dict with key
                list_file = str_file_d.get(key_of_dict)   #change the value of the key (the string) into list of integer

                # Decrypt it using Server's own private key
                recover_file = decrypt(list_file, d, n)

                # Receive the hash value
                hash_value, addr = serversocket.recvfrom(124928)
                int_check = integrity_check(str_file)    #Calculate the hash value
                print(int_check)  #print the hash value to check with the Client Side
                
                # Check if the hash value is equal to the calculation
                if int_check == hash_value.decode():
                    
                    # if they are the same, then write into the file
                    data.write(recover_file.encode())
                    
                else:  #if not the same, then print out someone had modified it
                    print('Someone had modified it in the transit!')
                    
    #If finish uploading, it will send the msg to the Client
    uploaded_msg = '\nFile is uploaded in Server'
    print(uploaded_msg)
    sent = serversocket.sendto(uploaded_msg.encode(), addr)
    
#If no, then pass, going to the download part
else: pass

print("\nWaiting to receive message on port " + str(port))

#Waiting for Client's download request
request_msg, addr = serversocket.recvfrom(1024)
print("\nClient's download request message:"+request_msg.decode())

#Response back to the Client for yes or no
response_msg = str(input('\nPlease enter the response(yes or no):'))
sent = serversocket.sendto(response_msg.encode(), addr)

#If yes, then start transfering the file to the Client
if response_msg.lower() == 'yes':

    print("\nWaiting to get the filename from Client on port " + str(port))

    #check if file exit
    i = 0
    while i <= 0:
        filename, addr = serversocket.recvfrom(1024)
        if os.path.exists(filename.decode()):
            reply_msg = '1'
            sent = serversocket.sendto(reply_msg.encode(),addr)
            i += 1
        else: #if doesn't exist, tell the Client to re-enter file name
            print('\nThe file that Client want to download does not exist')
            print('Asking Client to re-enter another filename...')
            print("\nWaiting to get the filename from Client on port " + str(port))
            reply_msg = '2'
            sent = serversocket.sendto(reply_msg.encode(),addr)
            
    filename = filename.decode() 
    
    if filename[-3::] == 'csv' or filename[-3::] == 'png' or filename[-3::] == 'pdf':
        second = 1.7
    else: second = 1.5
    
    key_of_dict = 1
    
    # Opening the file in the locol directory
    with open(filename,'rb') as file:
        
        # Uploading code for pdf, png, and jpg
        if filename[-3::] == 'pdf' or filename[-3::] == 'png' or filename[-3::] == 'jpg':

            # Uploading the first 1024 Bytes
            byte_data = base64.b64encode(file.read(1024))  # convert to byte
            str_data = byte_data.decode('UTF-8')  # convert to string

            # Encrypt the data with the Client's public key
            cipherdata = encrypt(str_data, client_public_key, client_public_key_n)
            cipherlist = json.dumps({str(key_of_dict): cipherdata})  #convert the list into string by using dict
            sent = serversocket.sendto(cipherlist.encode(), addr)

            # Calculate hash for the first read
            hash_value = integrity_check(cipherlist.encode())
            print('\nIntegrity Check \nHash value of the file:')
            print(hash_value)  #print the hash value to check with the Client side
            sent = serversocket.sendto(hash_value.encode(), addr)  #send the hash value to the Client
            
            time.sleep(second)  #Giving some time for the Client to decrypt the data
            
            while byte_data:  #if there is more binary data in the upoloading file, then continues
                
                key_of_dict = int(key_of_dict)
                key_of_dict = str(key_of_dict + 1)  #increasing the key of the dict
                byte_data = base64.b64encode(file.read(1024))  # convert to byte
                str_data = byte_data.decode('UTF-8')  # convert to string

                # Encrypt the data with the Server's public key
                cipherdata = encrypt(str_data, client_public_key, client_public_key_n)
                cipherlist = json.dumps({key_of_dict: cipherdata})  #convert the list into string by using dict
                sent = serversocket.sendto(cipherlist.encode(), addr)

                # Calculate each 1024Bytes' hash value
                hash_value = integrity_check(cipherlist.encode())
                print(hash_value)  #print the hash value to check with the Server side
                sent = serversocket.sendto(hash_value.encode(), addr) #send the hash value to the Client
                
                time.sleep(second)  #Giving some time for the Client to decrypt the data
                
        # if the file is not pdf, png, and jpg, then use this for other type of file
        else:
            # Uploading the first 1024 Bytes
            data = file.read(1024)
            str_data = data.decode()  # convert to string

            # Encrypt the data with the Server's public key
            cipherdata = encrypt(str_data, client_public_key, client_public_key_n)
            cipherlist = json.dumps({str(key_of_dict): cipherdata})  #convert the list into string by using dict
            sent = serversocket.sendto(cipherlist.encode(), addr)

            # calculated hash for the first read
            hash_value = integrity_check(cipherlist.encode())
            print('\nIntegrity Check \nHash value of the file:')
            print(hash_value)  #print the hash value to check with the Client side
            sent = serversocket.sendto(hash_value.encode(), addr)   #send the hash value to the Client
            
            time.sleep(second)  #Giving some time for the Server to decrypt the data
            
            while data:
                
                key_of_dict = int(key_of_dict)
                key_of_dict = str(key_of_dict + 1)
                data = file.read(1024)
                str_data = data.decode()
                cipherdata = encrypt(str_data, client_public_key, client_public_key_n)
                cipherlist = json.dumps({str(key_of_dict): cipherdata}) #convert the list into string by using dict
                sent = serversocket.sendto(cipherlist.encode(), addr)
                
                # calculated hash for the each read
                hash_value = integrity_check(cipherlist.encode())
                print(hash_value)  #print the hash value to check with the Client side
                sent = serversocket.sendto(hash_value.encode(), addr)
                
                time.sleep(second)  #Giving some time for the Client to decrypt the data
                
    # When it is done, the Server will receive a msg from Client saying it's finished downloading
    response_msg, addr = serversocket.recvfrom(1024)
    print(response_msg.decode())
    
#If no, then pass, end the program
else: pass

serversocket.close() #close the program/socket
