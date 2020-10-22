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
    # generate a 256 bit key based of user inputted key
    key = key_256(key)
    key_initial = key
    k = 0
    messagetemp = []
    if mode == "counter":
        for block in message:
            messagetemp.append(block)
        for i in range(len(message)):
            message[i] = bin(i)[2:]
            print(message[i])
            print(message)
            if ( len(message[i]) < BLOCKSIZE):
                for j in range(len(message[i]), BLOCKSIZE):
                    message[i] = "0" + message[i]
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
        block_ciphertext = (L[ROUNDS] + R[ROUNDS])
        if mode == "counter":
            block_ciphertext = xor(messagetemp[k], block_ciphertext)
            k += 1
        ciphertext += block_ciphertext
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
    # generate a 256 bit key based off the user inputted key
    key = key_256(key)
    key_initial = key
    k = 0
    ciphertexttemp = []
    if mode == "counter":
        for block in ciphertext:
            ciphertexttemp.append(block)
        for i in range(len(ciphertext)):
            ciphertext[i] = bin(i)[2:]
            if ( len(ciphertext[i]) < BLOCKSIZE):
                print(ciphertext[i])
                for j in range(len(ciphertext[i]), BLOCKSIZE):
                    ciphertext[i] = "0" + ciphertext[i]
        for block in ciphertext:
            L = [""] * (ROUNDS + 1)
            R = [""] * (ROUNDS + 1)
            L[0] = block[0:BLOCKSIZE//2]
            R[0] = block[BLOCKSIZE//2:BLOCKSIZE]
            for i in range(1, ROUNDS+1):
                L[i] = R[i - 1]
                R[i] = xor(L[i - 1], scramble(R[i - 1], i, key))
            block_message = (L[ROUNDS] + R[ROUNDS])
            block_message = xor(ciphertexttemp[k], block_message)
            message += block_message
            k += 1
    else:
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
            block_message = (L[0] + R[0])
            message += block_message
    return message

def key_256(key):
    return hashlib.sha256(key.encode()).hexdigest()

def subkeygen(s1, s2, i):
    return hashlib.sha256(s1.encode() + s2.encode()).hexdigest()

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
    #ciphertext = encryptMessage("B", "00000000", "counter")
    ciphertext = encryptMessage("B", "HELLOWORLDTIMTAM", "counter")
    #ciphertext = encryptMessage("B", "AAAAAAAA", "ebc")
    print("ciphertext = ", ciphertext)
    #print("AA = ", binaryToHex('10101010')[2:].upper())cl
    plaintext = decryptCipher("B", ciphertext, "counter")
    print("plaintext = ", plaintext, " ", len(plaintext))
    #print("plaintext = ", decryptCipher("B", ciphertext, "ebc"))