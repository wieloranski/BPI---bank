# -*- coding: utf-8 -*-
#!/bin/sh
import random;
from socket import*
import pickle;
import time
import textwrap
from random import SystemRandom
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from random import SystemRandom
from math import gcd

from Banknote import *;
#from blindedSignature import *;
import sys


#lista 100 banknotow#
M = [];

#listy potrzebne do rozdzielenia tajemnicy#
L = [[] for i in range(100)];
R = [[] for i in range(100)];

C = [[] for i in range(100)];
B = [[] for i in range(100)];
#tworzenie listy 100 banknotow
for i in range(100):

    banknote = Banknote();

    banknote.Y = 100;
    banknote.X = random.getrandbits(128);

    for j in range(100):

        I = '{0:b}'.format(random.getrandbits(32));
        banknote.I.append(I);

        #protokół rozdzielenia tajemnicy
        L_ = '{0:b}'.format(random.getrandbits(32));
        R_temp = int(L_,2) ^ int(I,2);
        R[i].append('{0:b}'.format(R_temp));
        L[i].append(L_);

        #protokół zobowiazania bitowego za pomocą funkcji haszującej nr. 1
        T = '{0:b}'.format(random.getrandbits(32));
        C_ = '{0:b}'.format(random.getrandbits(32));
        banknote.T.append(T);
        banknote.W.append(hash((T, C_, '{0:b}'.format(R_temp))));
        C[i].append(C_);

        # protokół zobowiazania bitowego za pomocą funkcji haszującej nr. 1
        S = '{0:b}'.format(random.getrandbits(32));
        B_ = '{0:b}'.format(random.getrandbits(32));
        banknote.S.append(S);
        banknote.U.append(hash((S, B_, L_)));
        B[i].append(B_);




    M.append(banknote);

print("KOMUNIKATY KONTROLNE PO STRONIE ALICE")
if M[99] != 0: print("1. utworzono 100 banknotow");
else: print("nie utworzono banknotow!!!");
if int(R[1][3], 2) ^ int(L[1][3], 2) == int(M[1].I[3],2):
    print("2. rozdzielenie tajemnicy XOR dziala");
else: print("rozdzielenie tajemnicy XOR nie dziala!!!");
if M[88].W[2] == hash((M[88].T[2], C[88][2], R[88][2])):
    print("3. zobowiazanie za pomoca haszu nr.1 dziala");
else:
    print("zobowiazanie za pomoca haszu nr.1 nie dziala!!!");

errors = 0
for i in range(100):
    for j in range(100):
        if M[i].U[j] == hash((M[i].S[j], B[i][j], L[i][j])):
            errors = errors + 0
        else:
            errors = errors + 1

if(errors == 0):
    print("4. zobowiazanie za pomoca haszu nr.2 dziala");
else:
    print("zobowiazanie za pomoca haszu nr.2 nie dziala!!!");

print("Czekam na klucz publiczny Banku...")
#print(M[1].U[1])
#print(M[1].S[1])
#print(B[1][1])
#print(L[1][1])
#print(hash((M[1].S[1], B[1][1], L[1][1])))
#print(hash((M[1].S[1], B[1][1], L[1][1])))

#pobieranie klucza publicznego
s1 = socket(AF_INET, SOCK_STREAM)
#host = socket.gethostname()
port = 12226
s1.bind(('', port))

s1.listen(1)

c, addr = s1.accept()
print('Got connection from', addr)
data = c.recv(1024)


publicKey = pickle.loads(data);
print("5. Otrzymalem klucz publiczny");

c.close()
test = []
#zakrywanie banknotu
Y_listOflists = []

#losowanie nieodkrywanego banknotu

k = random.randint(0,99)
k = 23

randomSocket = socket(AF_INET, SOCK_STREAM)
host = 'localhost'
port = 12444
randomSocket.bind((host, port))

randomSocket.listen(1)

c, addr = randomSocket.accept()
data = c.recv(64)


k = pickle.loads(data);
print("5. Otrzymalem klucz publiczny");

c.close()




for j in range(100):
    obj = pickle.dumps(M[j])
    objLength = len(obj)

    msg = int.from_bytes(obj, byteorder='big')
    test.append(msg)


    msg_part = textwrap.wrap(str(msg), 100)

    M_part_list = []
    Y_list = []

    for i in msg_part:
        msg = int(i)

        #zakrywanie
        r=random.randint(1,1)
        Z=int(r)
        while (gcd(r,publicKey.n)!=1):
            r=r+1

        Y = (msg * (Z**publicKey.e))%publicKey.n
        #power = pow(Z, publicKey.e)
        #Y = (msg * power) % publicKey.n
        # zrobić wyswietlanie 123123123 jako 0123123123. dopelnianie o zero!!!!!!!!!!!!!!!!!
        if ((i[0] == '0') & (i[0] != '')):
            if ((i[1] == '0') & (i[1] != '')):
                if((i[2] == '0') & (i[2] != '')):
                    if((i[3] == '0') & (i[3] != '')):
                        if((i[4] == '0') & (i[4] != '')): Y_list.append('00000' + str(Y))
                        else: Y_list.append('0000' + str(Y))
                    else: Y_list.append('000' + str(Y))
                else: Y_list.append('00' + str(Y))
            else:Y_list.append('0' + str(Y))
        else:Y_list.append(str(Y))


    Y_list.append(str(objLength))
    Y_listOflists.append(Y_list)
    print("Zakryto banknot numer" , j+1)

# hashuje wybrany banknot 'j'



r = SystemRandom().randrange(publicKey.n >> 10, publicKey.n)
msg = pickle.dumps(M[k-1]) # large message (larger than the modulus)

hash = SHA256.new()
hash.update(msg)
msgDigest = hash.digest()
msg_blinded = publicKey.blind(msgDigest, r)



#wysyłanie zakrytego banknotu do podpisu
for i in range(100):
    s2 = socket(AF_INET, SOCK_STREAM)
    host = 'localhost'
    port = 12342
    s2.connect((host, port));
    if(i == k - 1):

        object = pickle.dumps(msg_blinded)
        s2.send(object)

    else:

        object = pickle.dumps(Y_listOflists[i])
        s2.send(object)
        print("wyslano banknot numer", i+1)

s2.close()



print("Bank nie chce odkrywać banknotu numer", k)
#wysyłanie zob. bitowego

input("Press Enter to send L")
for i in range(100):
    if(i != k-1):
        s3 = socket(AF_INET, SOCK_STREAM)
        host = 'localhost'
        port = 12365
        s3.connect((host, port));
        object = pickle.dumps(L[i])
        s3.send(object)
        print("wyslano L banknotu numer: ", i+1)
        s3.close()
input("Press Enter to send R")
for i in range(100):
    if(i != k-1):
        s4 = socket(AF_INET, SOCK_STREAM)
        host = 'localhost'
        port = 12336
        s4.connect((host, port));
        object = pickle.dumps(R[i])
        s4.send(object)
        print("wyslano R banknotu numer: ", i+1)
        s4.close()

input("Press Enter to send B")
for i in range(100):
    if(i != k-1):
        s5 = socket(AF_INET, SOCK_STREAM)
        host = 'localhost'
        port = 12333
        s5.connect((host, port));

        object = pickle.dumps(B[i])
        s5.send(object)
        print("wyslano B banknotu numer: ", i+1)
        s5.close()
#print(B)
input("Press Enter to send C")
for i in range(100):
    if (i != k - 1):
        s6 = socket(AF_INET, SOCK_STREAM)
        host = 'localhost'
        port = 13333
        s6.connect((host, port));
        object = pickle.dumps(B[i])
        s6.send(object)
        print("wyslano C banknotu numer: ", i + 1)
        s6.close()

input("Press Enter to send Z wybranego banknotu")

s7 = socket(AF_INET, SOCK_STREAM)
host = 'localhost'
port = 13334
s7.connect((host, port));
object = pickle.dumps(r)
s7.send(object)
print("wyslano Z banknotu numer: ", k)
s7.close()














print("Czekam na ślepy podpis banknotu numer", k, "...")
s8 = socket(AF_INET, SOCK_STREAM)
host = 'localhost'
port = 12326
s8.bind(('', port))

s8.listen(5)

c, addr = s8.accept()
#print('Got connection from', addr)
data = c.recv(1024)
msg_blinded_signature = pickle.loads(data)

print("Odebralem ślepy podpis");

c.close()

msg_signature = publicKey.unblind(msg_blinded_signature[0], r)


if(str(publicKey.verify(msg_blinded, (msg_signature,)))):
    print("Podpis jest prawidłwy, podpisano banknot numer:" , k)













