import secrets
import hashlib


class Secp256r1(object):
    def __init__(self):
        # secp256r1 curve parameters
        # https://www.secg.org/sec2-v2.pdf
        self.a = 0x0000000000000000000000000000000000000000000000000000000000000000
        self.b = 0x0000000000000000000000000000000000000000000000000000000000000007
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        self.h = 1
        self.g = Point(self, 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


class Inf(object):
    def __init__(self, curve, x=None, y=None):
        self.x = x
        self.y = y
        self.curve = curve

    def __add__(self, other):
        if isinstance(other, Inf):
            return Inf()
        if isinstance(other, Point):
            return other


class Point(object):
    def __init__(self, curve, x, y):
        self.curve = curve
        self.x = x
        self.y = y
        self.p = self.curve.p

    def __m(self, p, q):
        if p.x == q.x:
            return (3 * p.x ** 2 + self.curve.a) * pow(2 * p.y, -1, self.p)
        else:
            return (p.y - q.y) * pow(p.x - q.x, -1, self.p)

    def __add__(self, other):
        if self.x == other.x and self.y != other.y:
            return Inf(self.curve)
        elif self.curve == other.curve:
            m = self.__m(self, other)
            x_r = (m ** 2 - self.x - other.x) % self.p
            y_r = -(self.y + m * (x_r - self.x)) % self.p
            return Point(self.curve, x_r, y_r)

    def __mul__(self, other):
        if isinstance(other, Inf):
            return Inf(self.curve)

        if other % self.curve.n == 0:
            return Inf(self.curve)
        if other < 0:
            addend = Point(self.curve, self.x, -self.y % self.p)
        else:
            addend = self
        result = Inf(self.curve)

        for bit in reversed([int(i) for i in bin(abs(other))[2:]]):
            if bit == 1:
                result += addend
            addend += addend
        return result
    
    def __rmul__(self, other):
        if isinstance(other, Inf):
            return Inf(self.curve)

        if other % self.curve.n == 0:
            return Inf(self.curve)
        if other < 0:
            addend = Point(self.curve, self.x, -self.y % self.p)
        else:
            addend = self
        result = Inf(self.curve)

        for bit in reversed([int(i) for i in bin(abs(other))[2:]]):
            if bit == 1:
                result += addend
            addend += addend
        return result

# curve = Secp256r1(curve="secp256r1")

# privKey = int("0x51897b64e85c3f714bba707e867914295a1377a7463a9dae8ea6a8b914246319", 16)
# print("privKey:", hex(privKey)[2:])

# pubKey = curve.g * privKey
# pubKeyCompressed = "0" + str(2 + pubKey.y % 2) + str(hex(pubKey.x)[2:])
# print("pubKey:", pubKeyCompressed)
# assert(pubKeyCompressed == "02f54ba86dc1ccb5bed0224d23f01ed87e4a443c47fc690d7797a13d41d2340e1a")


def generate_private_key():
    """Generate a new private key."""
    # Generate a random private key
    privKey = secrets.randbelow(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
    print("privKey", privKey)
    return privKey

def generate_public_key(privKey):
    """Generate a public key from a private key."""
    curve = Secp256r1()
    pubKey = curve.g * privKey
    pubKeyCompressed = "0" + str(2 + pubKey.y % 2) + str(hex(pubKey.x)[2:])
    print("pubKey:", pubKeyCompressed)
    return pubKeyCompressed,pubKey

def generate_keypair():
    """Generate a new keypair."""
    # Generate a random private key
    privKey = generate_private_key()
    # Generate a public key from a private key
    pubKeyCompressed,pubKey = generate_public_key(privKey)
    return privKey, pubKeyCompressed,pubKey


# https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages
def ecdsa_sign(privKey, message):
    """Sign a message with a private key."""
    # Calculate message hash
    hashBytes = hashlib.sha3_256(message.encode("utf8")).digest()
    h = int.from_bytes(hashBytes, byteorder="big")

    curve = Secp256r1()
    # Generate a random k
    k = secrets.randbelow(curve.n)
    # Generate a random point R with k
    r_point = k * curve.g
    # Calculate r
    r = r_point.x
    # Calculate s
    s = pow(k, -1, curve.n) * (h + r * privKey)
    # Return signature
    return (r, s)

def legendre_symbol(a, p):
        """ Compute the Legendre symbol """
        ls = pow(a, (p - 1) // 2, p)
        return -1 if ls == p - 1 else ls

def modular_sqrt(a, p):
    """ Find a quadratic residue (mod p) of a """
    # Partition p-1 to s * 2^e for an odd s
    s = p - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1

    # Find some 'n' with a legendre symbol n|p = -1.
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1
     
    x = pow(a, (s + 1) // 2, p)   # a guess of the square root
    b = pow(a, s, p)              # how much we're off with the guess
    g = pow(n, s, p)            # used to update
    r = e               # the exponent

    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)
        if m == 0:
            return x
        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m


def reconstruct_pubkey_point(pubKeyCompressed,pubK):
    curve = Secp256r1()
    x = int('0x'+pubKeyCompressed[2:],16)
    n = x**3 + curve.a * x + curve.b
    y = modular_sqrt(n, curve.p)
    if y % 2 != (int(pubKeyCompressed[1])-2):
        y = -y % curve.p
    pubKey = Point(curve,x, y)
    #print(pubK.x == x)
    #print(pubK.y)
    #print(y, y == pubK.y)
    return pubKey



def verify_signature(signed_message,signature,pubKey):#Compressed):
    """verify a ECDSA signature"""
    (r,s) = signature

    #reconstruct pubkey point
    curve = Secp256r1()
    new_pubKey = Point(curve,pubKey.x, pubKey.y)
    
    # Calculate message hash
    hashBytes = hashlib.sha3_256(signed_message.encode("utf8")).digest()
    h = int.from_bytes(hashBytes, byteorder="big")

    # calculate the modular inverse of the signature proof
    s_ = pow(s, -1, curve.n)
    #reconstruct the random point used in signature
    r_point = (new_pubKey * (r * s_) ) + ( (h * s_) * curve.g)
    r_ = r_point.x
    #vertify the signature by comparing the given r value with the one computed
    return(r_ == r)




def testing_sign_verify():
    privK,pubK_c,pubK = generate_keypair()
    try_pubk = reconstruct_pubkey_point(pubK_c,pubK)
    (r,s) = ecdsa_sign(privK, 'message')
    print(verify_signature('message',(r,s),try_pubk))
    

testing_sign_verify()
