import sys,hashlib,base64,binascii

ROUNDS = 8
BLOCKSIZE = 8
BLOCKSIZE_BITS = 64

def encryptMessage(key, message, mode):
    ciphertext = ""
    n = BLOCKSIZE  # 8 bytes (64 bits) per block
    message = [message[i: i + n] for i in range(0, len(message), n)]
    lengthOfLastBlock = len(message[len(message)-1])
    if ( lengthOfLastBlock < BLOCKSIZE):
        for i in range(lengthOfLastBlock, BLOCKSIZE):
            message[len(message)-1] += " "
    messagetemp = ""
    if mode == "counter":
        messagetemp = message
        for i in range(len(message)):
            message[i] = bin(i)[2:]
            print(message[i])
            print(message)
            if ( len(message[i]) < BLOCKSIZE):
                for j in range(len(message[i]), BLOCKSIZE):
                    message[i] = "0" + message[i]
        print("message encrypt = " , message)
    # generate a 256 bit key based of user inputted key
    #key = key_256(key)
    key_initial = key
    for block in message:
        L = [""] * (ROUNDS + 1)
        R = [""] * (ROUNDS + 1)
        L[0] = block[0:BLOCKSIZE//2]
        R[0] = block[BLOCKSIZE//2:BLOCKSIZE]
        for i in range(1, ROUNDS+1):
            L[i] = R[i - 1]
            if (mode == "cbc"):
                if (i == 1):
                    key = key_initial
                else:
                    key = subkeygen(L[i], key_initial, i) 
            R[i] = xor(L[i - 1], scramble(R[i - 1], i, key))
        ciphertext += (L[ROUNDS] + R[ROUNDS])
    if mode == "counter":
        messagetemp = "".join(messagetemp)
        print(messagetemp)
        print(len(messagetemp))
        ciphertext = xor(messagetemp, ciphertext)
    return ciphertext

def decryptCipher(key, ciphertext, mode):
    message = ""
    n = BLOCKSIZE  # 8 bytes (64 bits) per block
    # Split message into 64bit blocks
    ciphertext = [ciphertext[i: i + n] for i in range(0, len(ciphertext), n)]
    lengthOfLastBlock = len(ciphertext[len(ciphertext)-1])
    if ( lengthOfLastBlock < BLOCKSIZE):
        for i in range(lengthOfLastBlock, BLOCKSIZE):
            ciphertext[len(ciphertext)-1] += " "
    ciphertexttemp = ""
    if mode == "counter":
        ciphertexttemp = ciphertext
        for i in range(len(ciphertext)):
            ciphertext[i] = bin(i)[2:]
            if ( len(ciphertext[i]) < BLOCKSIZE):
                print(ciphertext[i])
                for j in range(len(ciphertext[i]), BLOCKSIZE):
                    ciphertext[i] = "0" + ciphertext[i]
        print("ciphertext decrypt = " , ciphertext)
    # generate a 256 bit key based off the user inputted key
    #key = key_256(key)
    key_initial = key
    for block in ciphertext:
        L = [""] * (ROUNDS + 1)
        R = [""] * (ROUNDS + 1)
        L[ROUNDS] = block[0:BLOCKSIZE//2]
        R[ROUNDS] = block[BLOCKSIZE//2:BLOCKSIZE]
        for i in range(8, 0, -1):
            if (mode == "cbc"):
                key = subkeygen(L[i], key_initial, i)
                if (i == 1):
                    key = key_initial
            R[i-1] = L[i]
            L[i-1] = xor(R[i], scramble(L[i], i, key))
        message += (L[0] + R[0])
    if mode == "counter":
        ciphertexttemp = "".join(ciphertexttemp)
        message = xor(ciphertexttemp,message)
    return message


# def key_256(key):
#     bkey= key + SECRET
#     return hashlib.sha256(bkey.encode()).hexdigest()

def subkeygen(s1, s2, i):
    #raise ValueError("CANNOT ACCESS")
    #print ("GENERATING KEY #" + str(i))
    #print ("S1: " + s1)
    #print ("S2: " + s2)
    result = hashlib.sha256(s1.encode('utf-8') + s2.encode('utf-8')).hexdigest()
    #print ("RESULT: " + result)
    return result

def scramble(block, NFeistelRound, key):
    key = stringToBinary(key)
    block = stringToBinary(str(block))

    key = binaryToInteger(key)
    block = binaryToInteger(block)

    res = pow((block * key), NFeistelRound)
    res = integerToBinary(res)

    return binaryToString(res)

#xor two strings
def xor(string1, string2):
    return ''.join(chr(ord(char1) ^ ord(char2)) for char1, char2 in zip(string1, string2))

def stringToBinary(string):
    return ''.join('{:08b}'.format(ord(char)) for char in string)

# binary to int
def binaryToInteger(binaryString):
    return int(binaryString, 2)

# int to binary
def integerToBinary(integer):
    return bin(integer)

# binary to string
def binaryToString(binaryString):
    #n = int(binaryString, 2)
    return ''.join(chr(int(binaryString[i: i + 8], 2)) for i in range(0, len(binaryString), 8))

def textToBinary(text):
    binaryTextList = []
    for char in text:
        binaryTextList.append(format(ord(char), 'b'))
    binaryText = ''.join(binaryTextList)
    return binaryText

def hexToBinary(hexString):
    dec = (int(hexString, 16))
    binary = bin(dec)
    return binary

def binaryToHex(binaryString):
    dec = (int(binaryString, 2))
    hexadecimal = hex(dec)
    return hexadecimal

if __name__ == "__main__":
    ciphertext = encryptMessage("B", "AA", "counter")
    print("ciphertext = ", ciphertext)
    #print("AA = ", binaryToHex('10101010')[2:].upper())cl
   # print("plaintext = ", decryptCipher("B", ciphertext, "counter"))