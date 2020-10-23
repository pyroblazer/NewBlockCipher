import sys,hashlib,base64,binascii
import numpy as np

ROUNDS = 8
BLOCKSIZE = 16
BLOCKSIZE_BITS = 256

RijndaelSBox = [
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
		]

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
            #print(message[i])
            #print(message)
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
                #print(ciphertext[i])
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
    #return hashlib.sha256(key.encode())
    return hashlib.sha256(key.encode()).hexdigest()

def subkeygen(s1, s2, i):
    return hashlib.sha256(s1.encode() + s2.encode()).hexdigest()

def scramble(block, NFeistelRound, key):
    sbox = generateKeyDependentSBox(key)
    key = stringToBinary(key)
    block = stringToBinary(str(block))

    #iterated
    #transposition
    keyi = 0
    for i in range(len(key)):
        keyi = keyi + int(key[i])
    
    for i in range(keyi):
        keyt = (keyi % len(block))
        while(len(block) % keyt != 0):
            keyt = keyt + 1
        nb = ''
        splt = [block[i:i+keyt] for i in range(0, len(block), keyt)]
        for i in range(keyt):
            for j in range(len(splt)):
                nb = nb + splt[j][i]
        block = nb

    #substitution
    ab = [block[i:i+8] for i in range(0, len(block), 8)]
    for i in range(len(ab)):
        row = binaryToInteger(ab[i][:2] + ab[i][6:8])
        column = binaryToInteger(ab[i][3:6])
        ab[i] = integerToBinary(sbox[16*row+column]).split('b')[1]
    block = ''.join(ab)

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

def getShift(key):
    """ Return the shift count based on the AES key."""
    shiftCount = 0
    for i, k in enumerate(key):
        #print(i)
        #print(k)
        shiftCount ^= k * (i+1) % (0xFF+1)
    return shiftCount

def getIndex(k, usedRow, usedColumn):
    """ Return the next available row or by doing the operation k&0x0F (where k is a byte in the key), 
    and the next available column by doing the operation k>>4."""
    coord = []
    coord.append(k&0x0F) # row
    coord.append(k>>4) # column
    if not coord[0] in usedRow:
        coord[0] = usedRow[0]
        usedRow.pop(usedRow.index(coord[0]))
    else:
        usedRow.pop(usedRow.index(coord[0]))

    if not coord[1] in usedColumn:
        coord[1] = usedColumn[0]
        usedColumn.pop(usedColumn.index(coord[1]))
    else:
        usedColumn.pop(usedColumn.index(coord[1]))
    return coord

def rotate(word, n):
	""" Returns a copy of the word shifted n bytes (chars)
	positive values for n shift bytes left, negative values shift right."""
	return word[n:]+word[0:n]

def shiftRow(row, shift, newSbox):
	""" Shift every item in the S-Boxes row by shift positions."""
	rowItems = [row, ((row*16)+16)+1]
	newSbox[rowItems[0]:rowItems[1]] = rotate(newSbox[rowItems[0]:rowItems[1]], shift)

def shiftColumn(column, shift, newSbox):
	""" Shift every item in the S-Boxes column by shift positions."""
	columnItems = [column, 256-(15-column)+1]
	newSbox[columnItems[0]:columnItems[1]:16] = rotate(newSbox[columnItems[0]:columnItems[1]:16], shift)

def swap(coords, newSbox):
	""" Switch the row and column from the tuple coords in the S-Box."""
	rowItems = [coords[0]*16, ((coords[0]*16)+16)]
	columnItems = [coords[1], 256-(15-coords[1])]
	rowCopy = newSbox[rowItems[0]:rowItems[1]]
	newSbox[rowItems[0]:rowItems[1]] = newSbox[columnItems[0]:columnItems[1]:16]
	newSbox[columnItems[0]:columnItems[1]:16] = rowCopy[:]

def sboxRound(key, newSbox):
    """ Runs a round of the S-Box block round."""
    shiftCount = getShift(key)
    usedRow = list(range(16))
    usedColumn = list(range(16))
    for i in key:
        coord = getIndex(i, usedRow, usedColumn)
        shiftRow(coord[0], shiftCount, newSbox)
        shiftColumn(coord[1], shiftCount, newSbox)
        swap(coord, newSbox)

# def sumOfKey(key):
#     sum = 0
#     for i in key:
#         sum += ord(i)
#     #print("sum = ", sum)
#     return sum

def mixKey(key):
    """ Returns an AES key where every byte in the output key is replaced by 
    the operation k^sum_of_key, where k is the respective byte in the input key 
    (this reduces collisions between similar keys)."""
    newKey = []
    #print("mixKey key = ", key)
    #print("sum = ", sumOfKey(key))
    for i in range(len(key)):
        #print("ord(" + key[i] + ") = ", ord(key[i]))
        newKey.append(key[i]^sum(key))
    #print("newKey = ", newKey)
    return newKey

def hexToKey(hexKey):
    """ Return a list of ints representing the AES hex key."""
    key = []
    for i in range(0, len(hexKey), 2):
            key.append(int(hexKey[i:i+2], base=16))
    return key

#Using the Hosseinkhani-Javadi method
def generateKeyDependentSBox(key):
    key = hexToKey(key)
    sbox = RijndaelSBox
    newSbox = sbox[:]  
    sboxKey = mixKey(key)  
    sboxRound(sboxKey[0:16], newSbox)
    sboxRound(sboxKey[16:32], newSbox)
    return newSbox

# XOR
# def generateKeyDependentSBox(key):
#     key = hexToBinary(key)[2:]
#     print("key length = ", len(key))
#     sbox = RijndaelSBox
#     newSbox = []
#     print("key = ", key)
#     for i in range(len(sbox)):
#         print("sbox[i] = ", sbox[i] , " | type = ", type(i))
#         print("key[i] = ", key[i], " | type = ", type(key[i]))
#         newSboxValue = sbox[i]^int(key[i])
#         newSbox.append(newSboxValue)
#     return newSbox

def swap(x, y):
    temp = x 
    x = y 
    y = temp
    return x, y

#using RC4 key scheduling
def generateKeyDependentPBox(key):
    Pbox = [i for i in range(8)]
    j = 0
    for i in range(8):
        j = (j+Pbox[i]+key[i % 8]) % 256
        Pbox[i], Pbox[j] = swap(Pbox[i], Pbox[j])
    return Pbox

def permutate(key, text):
    Pbox = generateKeyDependentPBox(key)
    newText = ""
    for i in range(8):
        newText += text[Pbox[i]]
    return newText

def ROTL8(x, shift):
    return ((x) << (shift)) | ((x) >> (8 - (shift)))

# def initializeRijndaelSBox(blockSize=256):
#     sbox = [0 for i in range(blockSize)]
#     p = np.uint8(1)
#     print("p = ", p)
#     q = np.uint8(1)
#     p = p ^ (p << 1) ^ (0x1B if (p & 0x80) else 0)
#     print("p = ", p)
#     q ^= q << 1
#     q ^= q << 2
#     q ^= q << 4
#     q ^= 0x09 if (q & 0x80) else 0
#     xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4)
#     sbox[p] = xformed ^ 0x63
#     while (p != 1):
#         p = p ^ (p << 1) ^ (0x1B if (p & 0x80) else 0)
#         print("p = ", p)
#         q ^= q << 1
#         q ^= q << 2
#         q ^= q << 4
#         q ^= 0x09 if (q & 0x80) else 0
#         xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4)
#         sbox[p] = xformed ^ 0x63
#     sbox[0] = 0x63
#     return sbox

if __name__ == "__main__":
    #ciphertext = encryptMessage("B", "00000000", "counter")
    ciphertext = encryptMessage("B", "I, Giorno Giovanna, have a dream", "counter")
    #ciphertext = encryptMessage("B", "AAAAAAAA", "ebc")
    print(ciphertext)
    #print("AA = ", binaryToHex('10101010')[2:].upper())cl
    plaintext = decryptCipher("B", ciphertext, "counter")
    print("plaintext = ", plaintext, " ", len(plaintext))
    #print("plaintext = ", decryptCipher("B", ciphertext, "ebc"))
    '''keyDependentSbox = generateKeyDependentSBox(key_256('B'))
    print(keyDependentSbox)
    print(len(set(keyDependentSbox)) == len(keyDependentSbox) )
    print(len(set(RijndaelSBox)) == len(RijndaelSBox) )'''
    