import os
from socket import socket, AF_INET, SOCK_STREAM
from sys import argv
import asnGenerator
from Cryptodome.Util.number import getPrime, inverse, GCD
from Cryptodome.Random.random import randint
from socket import *
from aesusage import *

def f(m, r):
    msg = m % r
    return msg

def m_from_f(m,r):
    msg = m % r
    return msg

def _generate_b(r):
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
    print("b = ", e)
    print("b_1 = ", d)
    return e, d

def start_server(port):
    print("Starting server...")
    serverIP = '127.0.0.1'
    buf_size = 1024  #Обычно 1024, но для быстрого ответа берем меньше
    sock = socket(AF_INET, SOCK_STREAM, proto=0)
    sock.bind((serverIP, port))
    print("Server started...")
    sock.listen(10)
    client_sock, client_addr = sock.accept()
    print('Client connected:', client_addr)
    if True:
        data = client_sock.recv(1024)
        print("Got p, r, t^a from client, saving to files 'p_r_ta_fromClient'")
        output = open('p_r_ta_fromClient','wb')
        output.write(data)
        output.close()

        p, r, t_a =  asnGenerator.decodeServer_p_r_ta(data)
        print("Got p, r, t^a from client:\n")
        print("r = ", r)
        print("p = ", p)
        print("t^a = ", t_a,"\n")

        print("--> Generating b, b' ...")
        b, b_1 = _generate_b(r)

        print("--> Calculating (t^a)^b ...")
        t_ab = pow(t_a,b,p)
        print("t^(ab) = ", t_ab)

        print("--> Generating asn structure of parameters...")
        asn_t_ab = asnGenerator.encodeServer_tab(t_ab)

        print("--> Sending client t^(ab)...")

        client_sock.send(asn_t_ab)

        data = client_sock.recv(1024)
        
        print("Got t^b, len from client, saving to files 'tb_len_fromClient'")
        output = open('tb_len_fromClient','wb')
        output.write(data)
        output.close()
        t_b, len_file =  asnGenerator.decodeServer_tb(data)
        print("Got t^b, len:\n")
        print("t^b = ", t_b,"\n len_file = ",len_file,"\n")

        print("--> Calculating (t^b)^b'=m ...")
        m = pow(t_b,b_1,p)
        #print("INT M = ",m)
        m = m_from_f(m,r)

        k = m % pow(2,256)
        k_bytes = k.to_bytes(32, 'big')
        fileNum=0
        while(True):
            k = int(input("1 - send file\n2 - receive file\n>>> "))
            if k == 1:
                path = str(input("Enter file path:\n>>> "))
                inputData = open(path,'rb').read()
                fileSize = len(inputData)
                encryptedDataAES, iv, lenCip  = AES_data_Encryption(path, k_bytes)
                asnCodedText = asnGenerator.encodeAES(fileSize,encryptedDataAES, iv)
                output = open("myfile","wb")
                output.write(asnCodedText)
                output.close()
                print("--> Sending file to client ...")
                client_sock.send(asnCodedText)
                print("SIze = ", len(asnCodedText))
            else:
                #data = b""
                #tmp = client_sock.recv(1024)
                #while len(tmp)>0:
                 #   data += tmp
                  #  tmp = client_sock.recv(1024)
                data = client_sock.recv(1000000)
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
                output = open("serverGotFile-"+str(fileNum),'wb')
                output.write(b)#decryptedText)
                output.close()
                fileNum+=1
                #path = str(input("Enter file path:\n>>> "))

        #print("OBR INT M = ",m)
        #m_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
      
        #print("m_bytes = ", m_bytes)
        #print("m = ", m_bytes.decode())
        #mes_dec(data, s)
    client_sock.close()

if __name__=="__main__":
    start_server(int(argv[1]))