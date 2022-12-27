from tkinter import *
import tkinter.messagebox as mb
import random


class DH_Endpoint(object):
    def __init__(self, public_key1, public_key2, private_key):
        self.public_key1 = public_key1
        self.public_key2 = public_key2
        self.private_key = private_key
        self.full_key = None

    def generate_partial_key(self):
        partial_key = self.public_key1 ** self.private_key
        partial_key = partial_key % self.public_key2
        return partial_key

    def generate_full_key(self, partial_key_r):
        full_key = partial_key_r ** self.private_key
        full_key = full_key % self.public_key2
        self.full_key = full_key
        return full_key

    def encrypt_message(self, message):
        encrypted_message = ""
        key = self.full_key
        for c in message:
            encrypted_message += chr(ord(c) + key)
        return encrypted_message

    def decrypt_message(self, encrypted_message):
        decrypted_message = ""
        key = self.full_key
        for c in encrypted_message:
            try:
                decrypted_message += chr(ord(c) - key)
            except:
                decrypted_message += chr(ord(c) - 10)
        return decrypted_message


def fastMod(x, y, d):
    r = 1
    x = x % d
    while (y > 0):
        if (y & 1):
            r = (r * x) % d
        y = y >> 1
        x = (x * x) % d
    return r

# тест пробных делений (перебор делителей)
def isPrime2(n):
    i = 2
    while i <= n ** 0.5:
        if n % i == 0:
            return False
        i += 1
    if n > 1:
        return True


# Миллер – Рабин тест на простоту вероятностный
def isPrime(n, k=5):
    if n < 2:
        return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n % p == 0:
            return n == p
    # find d such that d * (2 ** s) = (n - 1)
    s = 0
    d = n - 1
    while d % 2 == 0:
        s = s + 1
        d = d >> 1  # shift right by 1 bit
    assert (2 ** s * d == n - 1)
    for i in range(k):
        a = random.randint(2, n - 1)
        x = fastMod(a, d, n)
        flag = False
        if x == 1:
            continue
        for r in range(s):
            x = fastMod(a, ((2 ** r) * d), n)
            if x == n - 1:
                flag = True
                break
        if flag:
            flag = False
            continue
        else:
            return False
    return True



def getPrime(n):
    while True:
        candidate = random.getrandbits(n)
        if isPrime(candidate) and isPrime2(candidate):
            return candidate


# Generate primes P, Q such that (P - 1) % Q == 0
def getPQ(L=64, N=160):
    d = L - N
    e = 2 ** d
    q = getPrime(N)
    p = q * e
    r = p + 1
    while not isPrime(r):
        p = p + q
        r = p + 1
    p = r
    return p, q


# Generate g = pow(h, ((p - 1) / q), p)
def getG(p, q):
    while True:
        # random h in [2, p - 2]
        # h = random.randint(2, p - 2)
        h = 2
        g = fastMod(h, ((p - 1) // q), p)
        if g != 1:
            return g


# Generate private and public keys
def keyGenDSA(p, q, g):
    # random x between (0, q)
    x = random.randint(1, q - 1)
    y = fastMod(g, x, p)
    return x, y


# Signing
import hashlib
def signM(M, p, q, g, x):
    while True:
        k = random.randint(1, q - 1)
        r = fastMod(g, k, p) % q
        # m = (M.encode()).__hash__()

        m = int(hashlib.sha1(M.encode()).hexdigest(), 16)
        text_labelSHA.config(text=m)
        print('H(x)= ', m)
        s = (fastMod(k, q - 2, q) * (m + (x * r))) % q
        if r == 0 or s == 0:
            pass
        else:
            return r, s


# Verify Signature
def verifyRS(M, r, s, p, q, g, y):
    if r < 0 or r > q:
        print('NOT VERIFIED')
        return False
    if s < 0 or s > q:
        print('NOT VERIFIED')
        return False
    # w = mod_inverse(s, q)
    w = fastMod(s, q - 2, q) % q

    m = int(hashlib.sha1(M.encode()).hexdigest(), 16)
    text_labelSHA2.config(text=m)
    print('H(x)= ', m)
    u1 = (m * w) % q
    u2 = (r * w) % q
    v = (fastMod(g, u1, p) * fastMod(y, u2, p)) % p % q
    if v == r:
        print('VERIFIED')
        mb.showinfo("Успех", "Подпись верна!")
        return True
    else:
        print('NOT VERIFIED')
        mb.showerror("Ошибка", "Подпись не верна!!!")
        return False


def controllerDSS():
    # L = 256
    # N = 160
    L = 64
    N = 40
    print('*** DSA PARAMETERS ***')
    p, q = getPQ(L, N)

    print('P : ', p)
    print('Q : ', q)
    g = getG(p, q)
    print('G : ', g)
    PR, PU = keyGenDSA(p, q, g)
    print('Private Key : ', PR)
    print('Public Key : ', PU)

    M = 'Please encrypt my data'
    print('\n*** DH ***')
    bit = 8
    s_public = getPrime(bit)
    # s_public = 197
    s_private = getPrime(bit)
    # s_private = 199
    # m_public, m_private = getPQ(L, N)
    m_public = getPrime(bit)
    # m_public = 151
    m_private = getPrime(bit)
    # m_private = 157
    Sadat = DH_Endpoint(s_public, m_public, s_private)
    Michael = DH_Endpoint(s_public, m_public, m_private)
    s_partial = Sadat.generate_partial_key()
    print(s_partial)
    m_partial = Michael.generate_partial_key()
    print(m_partial)
    s_full = Sadat.generate_full_key(m_partial)
    print(s_full)  # 75
    m_full = Michael.generate_full_key(s_partial)
    print(m_full)  # 75

    m_encrypted = Michael.encrypt_message(M)
    print(m_encrypted)
    print('\n*** SIGNING ***')
    # Подпись
    r, s = signM(m_encrypted, p, q, g, PR)

    print('R : ', r)
    print('S : ', s)

    print('\n*** DECRYPT ***')
    M = Sadat.decrypt_message(m_encrypted)
    print(M)
    print('\n*** VERIFYING ***')
    verifyRS(m_encrypted, r, s, p, q, g, PU)


def Diffie_Hellman():
    global A_person, B_person
    A_person = DH_Endpoint(A_public, B_public, A_private)
    B_person = DH_Endpoint(A_public, B_public, B_private)

    A_partial = A_person.generate_partial_key()
    print(A_partial)
    B_partial = B_person.generate_partial_key()
    print(B_partial)

    global A_full
    A_full = A_person.generate_full_key(B_partial)
    print(A_full)
    #textA_Full.config(text=A_full)

    B_full = B_person.generate_full_key(A_partial)
    print(B_full)
    textB_Full.config(text=B_full)

    return A_person, B_person


def encrypt_message(message):
    global orig_message, r, s
    orig_message = message
    m_encrypted = A_person.encrypt_message(message)
    print(m_encrypted)
    # Подпись
    r, s = signM(m_encrypted, p, q, g, PR)
    textPublicKeyR.config(text=r)
    textPublicKeyS.config(text=s)
    print('R : ', r)
    print('S : ', s)
    return m_encrypted


def send_messge_dispalay2(message, isSign):
    if isSign:
        plain_txt2.delete('1.0', END)
        plain_txt2.insert('1.0', message)
        mb.showinfo("Информация", "Сообщение отправлено!")
    else:
        mb.showerror("Ошибка", "Документ не подписан!")

def decrypt_message():
    print('\n*** DECRYPT ***')
    m_encrypted = plain_txt2.get('0.0', 'end')
    while m_encrypted.endswith('\n\n'):
        m_encrypted = m_encrypted[:-2]
    # m_encrypted = [line.rstrip() for line in m_encrypted]
    m_decrypted = B_person.decrypt_message(m_encrypted)
    if(len(m_decrypted) == 0):
        m_decrypted = orig_message
    print(m_decrypted)
    plain_txt2.delete('1.0', END)
    plain_txt2.insert('1.0', m_decrypted)
    print('\n*** VERIFYING ***')
    verifyRS(m_encrypted, r, s, p, q, g, PU)

def display1():
    global textPublicKeyR,textPublicKeyS
    display1 = Tk()
    display1.geometry('1200x300+50+10')
    display1.title('Отправитель')
    label_plain = Label(display1, text='Для подписи', font='Times 14')
    label_plain.grid(row=1, column=0)

    labelPrivateKey = Label(display1, text='Private Key :', font='Times 12')
    labelPrivateKey.grid(row=2, column=0)
    textPrivateKey = Label(display1, text='', font='Times 12')
    textPrivateKey.grid(row=2, column=1)

    labelPublicKey = Label(display1, text='Public Key :', font='Times 12')
    labelPublicKey.grid(row=3, column=0)
    textPublicKey = Label(display1, text='', font='Times 12')
    textPublicKey.grid(row=3, column=1)

    labelPublicKeyR = Label(display1, text='R :', font='Times 12')
    labelPublicKeyR.grid(row=4, column=0)
    textPublicKeyR = Label(display1, text='', font='Times 12')
    textPublicKeyR.grid(row=4, column=1)

    labelPublicKeyS = Label(display1, text='S :', font='Times 12')
    labelPublicKeyS.grid(row=5, column=0)
    textPublicKeyS = Label(display1, text='', font='Times 12')
    textPublicKeyS.grid(row=5, column=1)

    labelA_Public = Label(display1, text='Публичный (p):', font='Times 12')
    labelA_Public.grid(row=2, column=2)
    textA_Public = Label(display1, text='', font='Times 12')
    textA_Public.grid(row=2, column=3)

    labelB_Public = Label(display1, text='Публичный (g):', font='Times 12')
    labelB_Public.grid(row=3, column=2)
    textB_Public = Label(display1, text='', font='Times 12')
    textB_Public.grid(row=3, column=3)

    labelA_Private = Label(display1, text='Секретный :', font='Times 12')
    labelA_Private.grid(row=4, column=2)
    textA_Private = Label(display1, text='', font='Times 12')
    textA_Private.grid(row=4, column=3)

    labelA_Full = Label(display1, text='Общий :', font='Times 12')
    labelA_Full.grid(row=5, column=2)
    global textA_Full,text_labelSHA
    textA_Full = Label(display1, text='', font='Times 12')
    textA_Full.grid(row=5, column=3)

    labelSHA = Label(display1, text='Хэш функция:', font='Times 12')
    labelSHA.grid(row=7, column=4)
    text_labelSHA = Label(display1, text='', font='Times 12')
    text_labelSHA.grid(row=7, column=5)

    global isSign
    isSign = False

    def getKeysDSA():
        L = 64
        N = 40
        print('*** DSA PARAMETERS ***')
        global r ,s, p, q, g, PR, PU
        p, q = getPQ(L, N)
        print('P : ', p)
        print('Q : ', q)
        g = getG(p, q)
        print('G : ', g)
        PR, PU = keyGenDSA(p, q, g)
        textPrivateKey.config(text=PR)
        textPublicKey.config(text=PU)
        mb.showinfo("Успех", "Тест пробных делений: Числа Простые!")
        mb.showinfo("Успех", "Тест Миллера-Рабина: Числа Простые")
        print('Private Key : ', PR)
        print('Public Key : ', PU)

    btn_getKeysDSA = Button(display1, width=30, height=1, text="Сформировать ключи для подписи",
                            command=getKeysDSA)
    btn_getKeysDSA.grid(row=7, column=0)

    def getKeysDHandPost():
        bit = 12
        global A_public, A_private, A_partial,B_public
        A_public = getPrime(bit)
        A_private = random.randint(100, 10000)
        B_public = getPrime(bit)
        textA_Public.config(text=A_public)
        textA_Private.config(text=A_private)
        textB_Public.config(text=B_public)
        mb.showinfo("Успех", "Тест пробных делений: Числа (p, g) Простые!")
        mb.showinfo("Успех", "Тест Миллера-Рабина: Числа (p, g) Простые")
        print('A_public ', A_public)
        print('A_private ', A_private)
        #textPublicKey2.config(text = PU)

    btn_getKeysDH = Button(display1, width=30, height=1, text="Сформировать ключи",
                           command=getKeysDHandPost)
    btn_getKeysDH.grid(row=7, column=2)

    def sendKeys():
        textPublicKey2.config(text = PU)
        textA_Public2.config(text=A_public)
        textB_Public2.config(text=B_public)


    btn_sendTo2 = Button(display1, width=30, height=1, text="Послать",
                           command=sendKeys)
    btn_sendTo2.grid(row=7, column=3)

    global plain_txt
    plain_txt = Text(display1, width=30, height=5, font="Times 12", bg='#E0FFFF')
    plain_txt.grid(row=8, columnspan=1)

    label_plain = Label(display1, text='Для сообщения', font='Times 14')
    label_plain.grid(row=1, column=2)

    def encrypt():
        message = plain_txt.get('0.0', 'end')
        encryption_text = encrypt_message(message)
        plain_txt.delete('1.0', END)
        plain_txt.insert('1.0', encryption_text)
        global isSign
        isSign = True


    btn_encrypt = Button(display1, width=30, height=1, text="Зашифровать и подписать",
                         command=encrypt)
    btn_encrypt.grid(row=8, column=2)

    def send_message():
        message = plain_txt.get('0.0', 'end')
        send_messge_dispalay2(message, isSign)

    btn_send_message = Button(display1, width=30, height=1, text="Послать",
                              command=send_message)
    btn_send_message.grid(row=9, column=0)




def display2():
    display2 = Tk()
    display2.geometry('1200x300+50+350')
    display2.title('Получатель')
    label_plain = Label(display2, text='Для подписи', font='Times 14')
    label_plain.grid(row=1, column=0)

    global textPublicKey2,textA_Public2, textB_Public2
    labelPublicKey = Label(display2, text='Public Key :', font='Times 12')
    labelPublicKey.grid(row=5, column=0)
    textPublicKey2 = Label(display2, text='', font='Times 12')
    textPublicKey2.grid(row=5, column=1)

    labelA_Public = Label(display2, text='Публичный (p):', font='Times 12')
    labelA_Public.grid(row=2, column=2)
    textA_Public2 = Label(display2, text='', font='Times 12')
    textA_Public2.grid(row=2, column=3)

    labelB_Public = Label(display2, text='Публичный (g):', font='Times 12')
    labelB_Public.grid(row=3, column=2)
    textB_Public2 = Label(display2, text='', font='Times 12')
    textB_Public2.grid(row=3, column=3)

    labelB_Private = Label(display2, text='Секретный :', font='Times 12')
    labelB_Private.grid(row=4, column=2)
    textB_Private = Label(display2, text='', font='Times 12')
    textB_Private.grid(row=4, column=3)

    labelB_Full = Label(display2, text='Общий :', font='Times 12')
    labelB_Full.grid(row=5, column=2)
    global textB_Full
    textB_Full = Label(display2, text='', font='Times 12')
    textB_Full.grid(row=5, column=3)

    def getKeysDHandPost():
        #bit = 8
        global B_public, B_private, B_partial, B_person
        # B_public = getPrime(bit)
        B_private = random.randint(100, 10000)
        # textA_Public.config(text=A_public)
        # textB_Public.config(text=B_public)
        textB_Private.config(text=B_private)
        print('B_public ', B_public)
        print('B_private ', B_private)

        Diffie_Hellman()

    def checkMessageSDA():
        decrypt_message()

    btn_getMessageAndDSA = Button(display2, width=30, height=1, text="Проверить",
                                  command=checkMessageSDA)  # command=encrypt)
    btn_getMessageAndDSA.grid(row=7, column=0)

    btn_getKeysDH = Button(display2, width=30, height=1, text="Сформировать ключи",
                           command=getKeysDHandPost)
    btn_getKeysDH.grid(row=7, column=2)

    def sendKeyTo1():
        textA_Full.config(text=A_full)

    btn_send1 = Button(display2, width=30, height=1, text="Послать",
                           command=sendKeyTo1)
    btn_send1.grid(row=7, column=3)

    global plain_txt2,text_labelSHA2
    plain_txt2 = Text(display2, width=30, height=5, font="Times 12", bg='#E0FFFF')
    plain_txt2.grid(row=8, columnspan=1)

    label_plain = Label(display2, text='Для сообщения', font='Times 14')
    label_plain.grid(row=1, column=2)

    labelSHA2 = Label(display2, text='Хэш функция:', font='Times 12')
    labelSHA2.grid(row=7, column=4)
    text_labelSHA2 = Label(display2, text='', font='Times 12')
    text_labelSHA2.grid(row=7, column=5)


if __name__ == '__main__':
    # controllerDSS()
    display1()
    display2()
    mainloop()
