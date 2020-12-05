import os
from socket import socket, AF_INET, SOCK_STREAM
from sys import argv
import millerrabin
from Cryptodome.Util.number import getPrime, inverse, GCD
from Cryptodome.Random.random import randint
import asnGenerator
import random
from aesusage import *

def f(m, r):
    msg = m% r
    return msg

def _generate_a(r):
    e = 0
    d = 0
    some = True
    while(some == True):
        e = randint(1,r-1)
        if (GCD(e,r)==1):
            d = inverse(e,r)
            if ((e*d)%r == 1):
                some = False
                break
    print("a = ", e)
    print("a_1 = ", d)
    return e, d
    

def start_client(host,port):
    print("--> Generating parameters...")
    #r = millerrabin.gen_prime(32)
    p = millerrabin.gen_prime(1024)
    i = 0
    r = p-1
    #while i<p:
    #    if (pow(i,r,p)==1):
    #        print(i,"^(",r,") = ",pow(i,r,p))
    #        #print("fount g = ",i)
    #    i+=1
   
    m = randint(2,r-1)

    print("Generated m, r, p:")
    print("m = ", m)
    print("r = ", r)
    print("p = ", p,"\n")

    #msg = str(input("Enter message...\n>>> "))
    #print("Your message is:\n",msg,"\n")
    #msg_bytes = str.encode(msg)
    #print("BYTES = ", msg_bytes)
    #print("INT = ", int.from_bytes(msg_bytes, "big"))
    
    print("--> Calculating t <- f(m)...")
    t = f(m, r) 
    if (t == 1):
        print("Wrong msg")
        return False
    print("t = ", t)
    
    print("--> Generating a, a' ...")
    a, a_1 = _generate_a(r) 
    #print("a*a_1 = ", (a*a_1)%r)
    print("--> Calculating t^a ...")
    cipher = pow(t,a,p)
    print("t^a = ", cipher)
    #print("t^(a*a_1) = ", pow(cipher,a_1,p))

    print("--> Generating asn structure of parameters...")
    asnCodedText = asnGenerator.encodeClient_p_r_ta(
        p,
        r,
        cipher
    )

    print("--> Sending server parameters...")

    #output = open('mymsg.ecrypted','wb')
    #output.write(asnCodedText)
    #output.close()

    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect((host, port))
    sock.send(asnCodedText)
    
    data = sock.recv(1024)
    t_ab = asnGenerator.decodeClient_tab(data)
    print("Got t^(ab) from server, saving to files 'tab_fromServer'")
    output = open('tab_fromServer','wb')
    output.write(data)
    output.close()
    
    print("Got t^(ab):\n")
    print('t^(ab) = ',t_ab,"\n")

    print("--> Calculating t^b ...")
    t_b = pow(t_ab,a_1,p)
    print("t^b = ", t_b)

    #print("--> Generating asn structure to send t_b ...")
    asnCoded_tb = asnGenerator.encodeClient_tb(
       t_b, 15
    )

    #print("--> Sending server t^b, len ...")
    sock.send(asnCoded_tb)

    k = m % pow(2,256)
    k_bytes = k.to_bytes(32, 'big')
    fileNum = 0
    while(True):
        k = int(input("1 - send file\n2 - receive file\n>>> "))
        if k==2:
            #data = b""
            #tmp = sock.recv(1024)
            #while len(tmp)>0:
            #    data += tmp
            #    tmp = sock.recv(1024)
            data = sock.recv(1000000)
            print("Got file, size is = ",len(data))
            #data = str(data,'utf-8')
            output = open("hzhz","wb")
            output.write(data)
            output.close()
            print("start decoding")
            iv, cipSize = asnGenerator.decodeAES(data)
            with open('~tmp', 'rb') as file:
                dataFile = file.read()
                print("start aes decryption")
                decryptedText = AES_data_Decryption(dataFile, k_bytes, iv)
                b = bytearray()
                i=0
                while i<cipSize:
                    b.append(decryptedText[i])
                    i=i+1
            print("decrypted")
            os.remove('~tmp')
            print("creating file")
            output = open("clientGotFile-"+str(fileNum),'wb')
            output.write(b)#decryptedText)
            output.close()
            fileNum+=1
        else:
            path = str(input("Enter file path:\n>>> "))
            inputData = open(path,'rb').read()
            fileSize = len(inputData)
            encryptedDataAES, iv, lenCip  = AES_data_Encryption(path, k_bytes)
            asnCodedText = asnGenerator.encodeAES(fileSize,encryptedDataAES, iv)
            output = open("myfile","wb")
            output.write(asnCodedText)
            output.close()
            print("--> Sending file to server ...")
            sock.send(asnCodedText)
            print("SIze = ", len(asnCodedText))


    #data = sock.recv(1024)

    #y = asn_dec_y(data) #Шаг 3
    #s = pow(y, a, p)
    #print("s = {}".format(s))
    #data = create_aes(s) #Шаг 4
    #sock.send(data)
    #sock.close()
    return

if __name__=="__main__":
    print("--> Starting client...")
    host = argv[1]  # localhost
    port = int(argv[2])
    start_client(host, port)
