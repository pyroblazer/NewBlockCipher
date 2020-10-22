import sys,hashlib,base64,binascii


ROUNDS = 8
BLOCKSIZE = 8
BLOCKSIZE_BITS = 64
# SECRET = "3f788083-77d3-4502-9d71-21319f1792b6"

def encryptMessage(key, message, mode):
    ciphertext = ""
    n = BLOCKSIZE  # 8 bytes (64 bits) per block

    message = hexToBinary(message)
    message = message[2:]
    print("message : ", message)

    # Split mesage into 64bit blocks
    message = [message[i: i + n] for i in range(0, len(message), n)]

    # append last block
    lengthOfLastBlock = len(message[len(message)-1])

    if ( lengthOfLastBlock < BLOCKSIZE):
        for i in range(lengthOfLastBlock, BLOCKSIZE):
            message[len(message)-1] += " "

    print(message)

    # generate a 256 bit key based of user inputted key
    key = hexToBinary(key)
    key = key[2:]
    #key = key_256(key)
    key_initial = key
    for block in message:
        #print ("Block: " + block)
        L = [""] * (ROUNDS + 1)
        R = [""] * (ROUNDS + 1)
        print("L : ", L)
        print("R : ", R)
        L[0] = block[0:BLOCKSIZE//2]
        R[0] = block[BLOCKSIZE//2:BLOCKSIZE]

        print ("L Initial: " + L[0])
        print ("R Initial: " + R[0])

        for i in range(1, ROUNDS+1):

            L[i] = R[i - 1]
            if (mode == "cbc"):
                if (i == 1):
                    key = key_initial
                else:
                    key = subkeygen(L[i], key_initial, i)
            R[i] = xor(L[i - 1], scramble(R[i - 1], i, key))

        ciphertext += (L[ROUNDS] + R[ROUNDS])
        print("L : ", L)
        print("R : ", R)

    print("cipherBin = ", ciphertext)
    ciphertext = binaryToHex(ciphertext)[2:]

    return ciphertext

def decryptCipher(key, ciphertext, mode):
    message = ""
    n = BLOCKSIZE  # 8 bytes (64 bits) per block

    ciphertext = hexToBinary(ciphertext)
    ciphertext = ciphertext[2:]
    # Split message into 64bit blocks
    ciphertext = [ciphertext[i: i + n] for i in range(0, len(ciphertext), n)]

    lengthOfLastBlock = len(ciphertext[len(ciphertext)-1])

    if ( lengthOfLastBlock < BLOCKSIZE):
        for i in range(lengthOfLastBlock, BLOCKSIZE):
            ciphertext[len(ciphertext)-1] += " "

    # generate a 256 bit key based off the user inputted key
    key = hexToBinary(key)
    key = key[2:]
    #key = key_256(key)
    key_initial = key
    for block in ciphertext:
        #print ("Block: " + block)
        L = [""] * (ROUNDS + 1)
        R = [""] * (ROUNDS + 1)
        L[ROUNDS] = block[0:BLOCKSIZE//2]
        R[ROUNDS] = block[BLOCKSIZE//2:BLOCKSIZE]

        # print ("L Initial: " + L[0])
        # print ("R Initial: " + R[0])

        for i in range(8, 0, -1):

            if (mode == "cbc"):
                key = subkeygen(L[i], key_initial, i)

                if (i == 1):
                    key = key_initial

            R[i-1] = L[i]
            L[i-1] = xor(R[i], scramble(L[i], i, key))


        message += (L[0] + R[0])

    print("messageBin = ", message)
    message = binaryToHex(message)[2:]

    return message


# def key_256(key):
#     bkey= key + SECRET
#     return hashlib.sha256(bkey.encode()).hexdigest()

def subkeygen(s1, s2, i):
    raise ValueError("CANNOT ACCESS")
    #print ("GENERATING KEY #" + str(i))
    #print ("S1: " + s1)
    #print ("S2: " + s2)
    result = hashlib.sha256(s1.encode('utf-8') + s2.encode('utf-8')).hexdigest()
    #print ("RESULT: " + result)
    return result

# def scramble(block, NFeistelRound, key):
#     key = stringToBinary(key)
#     block = stringToBinary(str(block))

#     key = binaryToInteger(key)
#     block = binaryToInteger(block)

#     res = pow((block * key), NFeistelRound)
#     res = integerToBinary(res)

#     return binaryToString(res)

def scramble(block, NFeistelRound, key):
    print("block : ", block)
    print("key : ", key)
    print("len block : ", len(block))
    res = xor(block, key)
    # if ( len(res) < len(block)):
    #     for i in range(len(res), len(block)):
    #         res = "0" + res
    # print("res = ", res)
    # print('res type = ', type(res))
    # res = textToBinary(res)
    print("res = ", res)
    print("res = ", int(res,2))
    print('res type = ', type(res))
    res = (int(res,2) << 1) % (pow(2,len(block))-1)
    res = bin(res)
    res = res[2:].zfill(len(block))
    print("finalres = ", res)
    # if res != '0010':
    #     raise ValueError("res = " + str(res) + ' != 0010')
    return res

# xor two strings
# def xor(string1, string2):
#     return ''.join(chr(ord(char1) ^ ord(char2)) for char1, char2 in zip(string1, string2))

def xor(text1, text2):
    print("text1 : ", text1)
    print("text2 : ", text2)

    n = len(text1)
    ans = "" 
    for i in range(n): 
        if (text1[i] == text2[i]):  
            ans += "0"
        else:  
            ans += "1"
    return ans 

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
    ciphertext = encryptMessage("B", "AA", "ebc")
    print("ciphertext = ", ciphertext)
    #print("AA = ", binaryToHex('10101010')[2:].upper())
    print("plaintext = ", decryptCipher("B", ciphertext, "ebc"))