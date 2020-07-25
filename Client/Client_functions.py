#Zhihao Pan
import hashlib
import math
import random

def integrity_check(data):
    hash_object = hashlib.sha256(data) #calculate the hash value of the data
    hex_dig = hash_object.hexdigest() #change the hash_object to hexdigest
    return hex_dig

def find_public_key(p,q):
    n = p*q
    phi_n = (p-1)*(q-1)
    while(1):
        #randomly get an e value
        e = random.randint(1,phi_n)
        #check if the public key e and phin are co-prime
        if (math.gcd(e,phi_n) == 1):
            return e

def find_private_key(p,q,e):
    n = p*q
    d = 1
    phi_n = (p-1)*(q-1)
    #iterate through values of d and check the Euclidean and co-prime
    while(1):
        if ((e*d)%phi_n) == 1:
            if (math.gcd(d,n) == 1):
                #added this because I had a case that d was the same
                if (d != e):
                    return d
        d += 1

def encrypt(msg,e,n):
    cipherNumber = []
    for i in msg:
        #calculate the encrypt number into list by the message in string
        cipherNumber.append((ord(i)**e)%n)
    return cipherNumber

def decrypt(msg,d,n):
    recovered = ""
    try:
        for i in msg:
            #add the character into string by using the encrypt number in list
            recovered = recovered + chr((i**d)%n)
    except:
        print('\ntry again because NONETYPE Error exist in the decrypt function')
    return recovered


