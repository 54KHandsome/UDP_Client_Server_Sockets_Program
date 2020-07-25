#Zhihao Pan
#Client
import sys
from Client_functions import integrity_check, find_public_key, find_private_key, encrypt, decrypt
import socket
import json
import base64
import time
import os
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
port = 9999
serverAddr = ('10.0.0.7', port)

#Calculating the n,e,and d
p = int(input('Please input prime number for p:'))
q = int(input('Please input prime number for q:'))
n = p*q
e = find_public_key(p,q)
print('Found public key e:',e)
d = find_private_key(p,q,e)
print('Found private key d:',d)

#sending the public key
print("\nSending Client's public key...")
e = str(e)
s.sendto(e.encode(),serverAddr)
n = str(n)
s.sendto(n.encode(),serverAddr)
n = int(n)

#receiving the public key
server_public_key, addr = s.recvfrom(1024) #receiving the server's public key
server_public_key = int(server_public_key.decode())
server_public_key_n, addr = s.recvfrom(1024) #receiving the server's n
server_public_key_n = int(server_public_key_n.decode())

print("\nRecieved the Server's public key:",server_public_key)

#Client request to upload a file
request_msg = str(input('\nPlease enter upload request:'))
s.sendto(request_msg.encode(),serverAddr)

print('\nWaiting to receive message..')

#Waiting for Server's yes or no for uploading the file
response_msg, addr = s.recvfrom(1024)
print("\nServer's response message:"+response_msg.decode())

#If Server said yes, then start uploading
if response_msg.decode().lower() == 'yes':

    #Entering the file name
    filename = str(input('\nPlease input the file name with the type (Ex: abc.txt):'))

    #Check if file exist in local directory
    #If don't exist, then re-enter the filename
    i = 0
    while i <= 0:
        if os.path.exists(filename):
            i += 1
        else:
            print('\nThe file does not exist')
            filename = str(input('\nPlease input the file name again with the type (Ex: abc.txt):'))
    
    s.sendto(filename.encode(),serverAddr) #send the filename to the Server

    #set the time(second) for time
    if filename[-3::] == 'csv' or filename[-3::] == 'png' or filename[-3::] == 'pdf':
        second = 1.7
    else: second = 1.5
    
    key_of_dict = 1
    
    #Opening the file in the locol directory
    with open(filename,'rb') as file:
        
        #Uploading code for pdf, png, and jpg
        if filename[-3::] == 'pdf' or filename[-3::] == 'png' or filename[-3::] == 'jpg':

            #Uploading the first 1024 Bytes
            byte_data = base64.b64encode(file.read(1024)) #convert to byte
            str_data = byte_data.decode('UTF-8')  #convert to string

            #Encrypt the data with the Server's public key
            cipherdata = encrypt(str_data,server_public_key,server_public_key_n)
            cipherlist = json.dumps({str(key_of_dict):cipherdata})  #convert the list into string by using dict
            s.sendto(cipherlist.encode(),serverAddr)

            #Calculate hash for the first read
            hash_value = integrity_check(cipherlist.encode())
            print('\nIntegrity Check \nHash value of the file:')
            print(hash_value)  #print the hash value to check with the Server side
            s.sendto(hash_value.encode(),serverAddr)  #send the hash value to the Server
            
            #I used this because the decrypt calculation is slow in the Server side
            #So I use a time sleep to pause # second to wait for the Server
            #If I don't put this here, the Server would receive too much buffer from the Client and it will break
            time.sleep(second)
            
            while byte_data:  #if there is more binary data in the upoloading file, then continues
                
                key_of_dict = int(key_of_dict)
                key_of_dict = str(key_of_dict + 1)  #increasing the key of the dict
                byte_data = base64.b64encode(file.read(1024))  #upload the other bytes
                str_data = byte_data.decode('UTF-8')  #convert to string

                # Encrypt the data with the Server's public key
                cipherdata = encrypt(str_data,server_public_key,server_public_key_n)
                cipherlist = json.dumps({key_of_dict:cipherdata})  #convert the list into string by using dict
                s.sendto(cipherlist.encode(),serverAddr)

                #Calculate each 1024Bytes' hash value
                hash_value = integrity_check(cipherlist.encode())
                print(hash_value)  #print the hash value to check with the Server side
                s.sendto(hash_value.encode(),serverAddr) #send the hash value to the Server
                
                time.sleep(second)  #Giving some time for the Server to decrypt the data
                
        #if the file is not pdf, png, and jpg, then use this for other type of file
        else:
            # Uploading the first 1024 Bytes
            data = file.read(1024)
            str_data = data.decode()  #convert to string

            # Encrypt the data with the Server's public key
            cipherdata = encrypt(str_data, server_public_key, server_public_key_n)
            cipherlist = json.dumps({str(key_of_dict): cipherdata})  #convert the list into string by using dict
            s.sendto(cipherlist.encode(), serverAddr)

            # calculated hash for the first read
            hash_value = integrity_check(cipherlist.encode())
            print('\nIntegrity Check \nHash value of the file:')
            print(hash_value)  #print the hash value to check with the Server side
            s.sendto(hash_value.encode(), serverAddr)  #send the hash value to the Server
            
            time.sleep(second)  #Giving some time for the Server to decrypt the data
            
            while data:  #if there is more binary data in the upoloading file, then continues
                
                key_of_dict = int(key_of_dict)
                key_of_dict = str(key_of_dict + 1)
                data = file.read(1024)
                str_data = data.decode()

                # Encrypt the data with the Server's public key
                cipherdata = encrypt(str_data, server_public_key, server_public_key_n)
                cipherlist = json.dumps({key_of_dict: cipherdata}) #convert the list into string by using dict
                s.sendto(cipherlist.encode(), serverAddr)

                # calculated hash for the each read
                hash_value = integrity_check(cipherlist.encode())
                print(hash_value)  #print the hash value to check with the Server side
                s.sendto(hash_value.encode(), serverAddr)
                
                time.sleep(second)  #Giving some time for the Server to decrypt the data
                
    #When it is done, the Client will receive a msg from Server saying it's finished uploading
    response_msg, addr = s.recvfrom(1024)
    print(response_msg.decode())
    
#If no, then pass, going to the download part
else: pass


#Download the file
request_msg = str(input('\nPlease enter download request:'))
s.sendto(request_msg.encode(),serverAddr)

print('\nWaiting to receive message..')

#Waiting for Server's reply
response_msg, addr = s.recvfrom(1024)
print("\nServer's response message:"+response_msg.decode())

#If Server said yes, then start downloading
if response_msg.decode().lower() == 'yes':
    key_of_dict = 1
    
    # Entering the file name
    filename = str(input('\nPlease enter the filename with type that you want to download (Ex: abc.txt):'))

    #Check if file exit
    #If it exit, then deleted the old one
    if os.path.exists(filename):
        os.remove(filename)
    
    s.sendto(filename.encode(),serverAddr)

    #If the file doesn't exist in the Server, then re-enter the filename
    ii = 0
    while ii <= 0:
        response_msg, addr = s.recvfrom(1024)
        if int(response_msg.decode()) == 1:
            ii += 1
        elif int(response_msg.decode()) == 2:
            filename = str(input('\nServer does not have that file \nPlease again enter the filename with type that you want to download (Ex: abc.txt):'))
            s.sendto(filename.encode(),serverAddr)
    
    with open(filename,'a+b') as data:
        
        # Receiving code for pdf, png, and jpg
        if filename[-3::] == 'pdf' or filename[-3::] == 'png' or filename[-3::] == 'jpg':

            # Recieving from the Server
            receive_byte_file, addr = s.recvfrom(124928)  # 124928
            receive_str_file = receive_byte_file.decode('UTF-8')  #convert to string
            receive_str_file_d = json.loads(receive_str_file)  #string to dict with key
            receive_list_file = receive_str_file_d.get(str(key_of_dict))   #change the value of the key (the string) into list of integer

            # Decrypt it using Client's own private key
            receive_recover_file = decrypt(receive_list_file, d, n)

            # Receive the hash value
            receive_hash_value, addr = s.recvfrom(124928)
            print('\nIntegrity Check \nHash value of the file:')
            receive_int_check = integrity_check(receive_byte_file)  #Calculate the hash value
            print(receive_int_check)  #print the hash value to check with the Server Side

            # Check if the hash value is equal to the calculation
            if receive_int_check == receive_hash_value.decode():
                
                # if they are the same, then write into the file
                receive_recover_file = receive_recover_file.encode('UTF-8')
                data.write(base64.decodebytes(receive_recover_file))  #change to bytes and write to the file
                
            else:  #if not the same, then print out someone had modified it
                print('Someone had modified it in the transit!')
                
            while (sys.getsizeof(receive_list_file)!=28):  #this will end when it reach to the end size
                
                key_of_dict = int(key_of_dict)
                key_of_dict = str(key_of_dict + 1)  #increasing the key of the dict
                receive_byte_file, addr = s.recvfrom(124928)  #Receiving the file
                receive_str_file = receive_byte_file.decode('UTF-8')  #convert to string
                receive_str_file_d = json.loads(receive_str_file)  #string to dict with key
                receive_list_file = receive_str_file_d.get(key_of_dict)   #change the value of the key (the string) into list of integer

                # Decrypt it using Client's own private key
                receive_recover_file = decrypt(receive_list_file, d, n)

                # Receive the hash value
                receive_hash_value, addr = s.recvfrom(124928)
                receive_int_check = integrity_check(receive_byte_file)  #Calculate the hash value
                print(receive_int_check)  #print the hash value to check with the Server Side
                
                # Check if the hash value is equal to the calculation
                if receive_int_check == receive_hash_value.decode():
                    
                    # if they are the same, then write into the file
                    receive_recover_file = receive_recover_file.encode('UTF-8')
                    data.write(base64.decodebytes(receive_recover_file))
                    
                else:  #if not the same, then print out someone had modified it
                    print('Someone had modified it in the transit!')
                    
        # if the file is not pdf, png, and jpg, then use this for other type of file
        else:
            receive_str_file, addr = s.recvfrom(124928)
            receive_str_file_d = json.loads(receive_str_file.decode())  #string to dict with key
            receive_list_file = receive_str_file_d.get(str(key_of_dict))   #change the value of the key (the string) into list of integer

            # Decrypt it using Client's own private key
            receive_recover_file = decrypt(receive_list_file, d, n)

            # Receive the hash value
            receive_hash_value, addr = s.recvfrom(124928)
            print('\nIntegrity Check \nHash value of the file:')
            receive_int_check = integrity_check(receive_str_file)    #Calculate the hash value
            print(receive_int_check)  #print the hash value to check with the Server Side
            
            # Check if the hash value is equal to the calculation
            if receive_int_check == receive_hash_value.decode():
                
                # if they are the same, then write into the file
                data.write(receive_recover_file.encode())
                
            else:  #if not the same, then print out someone had modified it
                print('Someone had modified it in the transit!')
                
            while (sys.getsizeof(receive_list_file)!=28):  #this will end when it reach to the end size
                
                key_of_dict = int(key_of_dict)
                key_of_dict = str(key_of_dict + 1)
                receive_str_file, addr = s.recvfrom(124928)  # 124928
                receive_str_file_d = json.loads(receive_str_file.decode())  #string to dict with key
                receive_list_file = receive_str_file_d.get(key_of_dict)   #change the value of the key (the string) into list of integer

                # Decrypt it using Client's own private key
                receive_recover_file = decrypt(receive_list_file, d, n)

                # Receive the hash value
                receive_hash_value, addr = s.recvfrom(124928)
                receive_int_check = integrity_check(receive_str_file)    #Calculate the hash value
                print(receive_int_check)  #print the hash value to check with the Server Side
                
                # Check if the hash value is equal to the calculation
                if receive_int_check == receive_hash_value.decode():
                    
                    # if they are the same, then write into the file
                    data.write(receive_recover_file.encode())
                    
                else:  #if not the same, then print out someone had modified it
                    print('Someone had modified it in the transit!')
                    
    # If finish downloading, it will send the msg to the Server
    download_msg = '\nFile is downloaded in Client'
    print(download_msg)
    s.sendto(download_msg.encode(), addr)
    
#If no, then pass, end the program
else: pass

s.close() #close the program/socket
