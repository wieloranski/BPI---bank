# -*- coding: utf-8 -*-
#!/bin/sh
from Crypto.PublicKey import RSA
import ast
from socket import*;
import pickle;
import time;
import random

key = RSA.generate(1024,e=17)
public_key = key.publickey()
private_key = key.exportKey("PEM")
print("1. Klucze zostaly wygenerowane")

#message = 1231234234234;

publickey = key.publickey();
#encrypted = publickey.encrypt(message, 32)
#decrypted = key.decrypt(ast.literal_eval(str(encrypted)))



input("Press ENTER to send public key")
#Wysylanie klucza publicznego
s1 = socket(AF_INET, SOCK_STREAM)
host = 'localhost'
port = 12226

s1.connect((host, port))
s1.send(pickle.dumps(publickey));
print("2. Klucz publiczny zostal wyslany do Alice")
s1.close()

time.sleep(1)

#input("Press ENTER to send number of random banknote")
#losowy banknot
k = random.randint(0,99)

s = socket(AF_INET, SOCK_STREAM)
host = '127.0.0.1'
port = 12444

s.connect((host, port))
s.send(pickle.dumps(k));
#print("wysylano decyzje nie odkrywania banknotu numer", k)
s.close()



#odbieranie zakrytego banknotu
blindedMsg_list = []
data = []
s2 = socket(AF_INET, SOCK_STREAM)
host = 'localhost'
port = 12342
s2.bind(('',port))
s2.listen(1)
for i in range(100):

    c,addr = s2.accept()

    #print('Got connection from', addr)
    data = c.recv(50000000)
    blindedMsg_list.append(pickle.loads(data));
    print("odebrano zakryty banknot numer", i+1)
c.close()


#ślepy podpis i odkrywanie banknotu
Z = 1

index = 0
M = [[] for i in range(100)]
counter = 0
for i in blindedMsg_list:
    if(index == k-1):
        M[k-1] = i
        msg_blinded = i
    else:
        M_part_list = []
        for y in i:
            div = int(y)//pow(Z, public_key.e)
            M_part = div%public_key.n

            if((y[0]=='0') & (y[0] != '')):
                if ((y[1] == '0') & (y[1] != '')):
                    if ((y[2] == '0') & (y[2] != '')):
                        if ((y[3] == '0') & (y[3] != '')):
                            if ((y[4] == '0') & (y[4] != '')): M_part_list.append('00000' + str(M_part))
                            else: M_part_list.append('0000' + str(M_part))
                        else: M_part_list.append('000' + str(M_part))
                    else: M_part_list.append('00' + str(M_part))
                else:M_part_list.append('0' + str(M_part))
            else:M_part_list.append(str(M_part))

        M_unblinded = int(''.join(M_part_list))//100000

        objLength = M_part_list[len(M_part_list)-1]
        obj1 = int.to_bytes(M_unblinded, int(objLength), byteorder = 'big')
        banknote = pickle.loads(obj1, errors="")
        M[index] = banknote
        print("odkryto banknot numer", index + 1, "(" , M_unblinded, ")")
        #counter = counter + 1
    index = index + 1

for i in range(100):
    if (i != k -1):
        if(M[i].Y == 100): print("Zgadza się wartość banknotu nr", i+ 1)

#input("Sprawdz czy banknoty sie różnią")
error = 'false'
for i in range(100):
    if( i != k -1):
        for j in range (100):
            if(j != i):
                if(M[i] == M[j]):
                    error = 'true'
                    print("Identyfikstor ten sam . Banknoty:", i+1 , j+1)
if(error == 'false'):
    print("ID banknotów się różnią")

#input("Sprawdz czy wszystkie banknoty identyfikują Alice ")
#odbieranie zob. bit. L
L = [[] for i in range(100)];
s3 = socket(AF_INET, SOCK_STREAM)
host = 'localhost'
port = 12365
s3.bind(('',port))
s3.listen(1)
for i in range(100):
    if(i != k-1):
        c,addr = s3.accept()

        #print('Got connection from', addr)
        data = c.recv(3900)
        L[i] = pickle.loads(data);
        print("odebrano L banknotu" , i+1)
c.close()

#odbieranie zob. bit. R
R = [[] for i in range(100)];
s4 = socket(AF_INET, SOCK_STREAM)
host = 'localhost'
port = 12336
s4.bind(('',port))
s4.listen(1)
for i in range(100):
    if(i != k-1):
        c,addr = s4.accept()

        #print('Got connection from', addr)
        data = c.recv(3900)
        R[i] = pickle.loads(data);
        print("odebrano R banknotu" , i+1)
c.close()
error = 'true'
for i in range(100):
    if (i != k - 1):
        for j in range(100):
            if int(R[i][j], 2) ^ int(L[i][j], 2) == int(M[i].I[j],2):
                error = 'false'
            else: error = 'true'
if(error == 'false'): print("Liczba banknotów: 100, identyfikuje Alice");
else : print("Liczba banknotów: 100, identyfikuje Alice");
#odbieranie B
B = [[] for i in range(100)];
s5 = socket(AF_INET, SOCK_STREAM)
host = 'localhost'
port = 12333
s5.bind(('',port))
s5.listen(1)
for i in range(100):
    if(i != k-1):
        c,addr = s5.accept()

        #print('Got connection from', addr)
        data = c.recv(3900)
        B[i] = pickle.loads(data);

        print("odebrano B banknotu" , i+1)
c.close()
error = 'true'
#print(B)
if M[1].U[1] == hash((M[1].S[1], B[1][1], L[1][1])):
    print("zobowiazanie za pomoca haszu nr.2 dziala");
else:
    print("zobowiązanie bitowe za pomocą f. hashującej nr 1. działa");

#print(M[1].U[1])
#print(M[1].S[1])
#print(B[1][1])
#print(L[1][1])
#print(hash((M[1].S[1], B[1][1], L[1][1])))

#odbieranie C
C = [[] for i in range(100)];
s6 = socket(AF_INET, SOCK_STREAM)
host = 'localhost'
port = 13333
s6.bind(('',port))
s6.listen(1)
for i in range(100):
    if(i != k-1):
        c,addr = s6.accept()

        #print('Got connection from', addr)
        data = c.recv(3900)
        C[i] = pickle.loads(data);
        print("odebrano C banknotu" , i+1)
c.close()
error = 'true'
if M[88].W[2] == hash((M[88].T[2], C[88][2], R[88][2])):
    print("3. zobowiazanie za pomoca haszu nr.1 dziala");
else:
    print("zobowiązanie bitowe za pomocą f. hashującej nr 2. działa");



#odbieranie Z

s7 = socket(AF_INET, SOCK_STREAM)
host = 'localhost'
port = 13334
s7.bind(('',port))
s7.listen(1)

c,addr = s7.accept()

#print('Got connection from', addr)
data = c.recv(3900)
r = pickle.loads(data);
print("odebrano Z banknotu" , k)
c.close()



#msg_unblinded = public_key.unblind(msg_blinded, r)


msg_blinded_signature = key.sign(msg_blinded, 0)

print("Utworzono ślepy podpis pod banknotem numer" , k)
input("Press enter to send blinded signature")

s7 = socket(AF_INET, SOCK_STREAM)
host = 'localhost'
port = 12326

s7.connect((host, port))
s7.send(pickle.dumps(msg_blinded_signature));
print("ślepy podpis został wysłany")
s7.close()
