from Crypto.PublicKey import RSA
import random

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def multiplicative_inverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi

    while e > 0:
        temp1 = temp_phi/e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2

        x = x2- temp1* x1
        y = d - temp1 * y1

        x2 = x1
        x1 = x
        d = y1
        y1 = y

    if temp_phi == 1:
        return d + phi

def is_prime(num):
    return True
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in xrange(3, int(num**0.5)+2, 2):
        if num % n == 0:
            return False
    return True

def generate_keypair(p, q, e):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
    #n = pq
    n = p * q

    #Phi is the totient of n
    phi = (p-1) * (q-1)

    #Choose an integer e such that e and phi(n) are coprime
    #e = random.randrange(1, phi)

    #Use Euclid's Algorithm to verify that e and phi(n) are comprime
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    #Use Extended Euclid's Algorithm to generate the private key
    d = multiplicative_inverse(e, phi)

    #Return public and private keypair
    #Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))

def encrypt(pk, plaintext):
    #Unpack the key into it's components
    key, n = pk
    #Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = [(ord(char) ** key) % n for char in plaintext]
    #Return the array of bytes
    return cipher

def decrypt(pk, ciphertext):
    #Unpack the key into its components
    key, n = pk
    #Generate the plaintext based on the ciphertext and key using a^b mod m
    plain = [chr((char ** key) % n) for char in ciphertext]
    #Return the array of bytes as a string
    return ''.join(plain)


if __name__ == '__main__':
    import base64
    rsa_public_key_file_path = "C:\\Noa\\Projects\\Ctf\\ctf3\\poor_rsa\\key.pub"
    rsa_public_key_file = open(rsa_public_key_file_path, "rb")
    rsa_public_key = rsa_public_key_file.read()
    print rsa_public_key

    public_key = RSA.importKey(rsa_public_key)
    n = long(public_key.n)
    e = long(public_key.e)
    print n
    print e
    #Use http://www.factordb.com to find the factors for n
    #This is why you should always use very big factors for RSA encryption
    p = 863653476616376575308866344984576466644942572246900013156919
    q = 965445304326998194798282228842484732438457170595999523426901
    print p * q
    print "RSA Encrypter/ Decrypter"
    print "Generating your public/private keypairs now . . ."
    public, private = generate_keypair(p, q, int(e))
    print "Your public key is ", public
    print " and your private key is ", private
    d = private[0]
    print d
    key = RSA.construct((n, e, d))
    print key.exportKey()
    encrypted_msg = base64.b64decode("Ni45iH4UnXSttNuf0Oy80+G5J7tm8sBJuDNN7qfTIdEKJow4siF2cpSbP/qIWDjSi+w=")
    print key.decrypt(encrypted_msg)