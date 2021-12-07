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
    return pubKeyCompressed

def generate_keypair():
    """Generate a new keypair."""
    # Generate a random private key
    privKey = generate_private_key()
    # Generate a public key from a private key
    pubKeyCompressed = generate_public_key(privKey)
    return privKey, pubKeyCompressed

print(generate_keypair())

# https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages
def ecdsa_sign(privKey, message):
    """Sign a message with a private key."""
    # Calculate message hash
    m = hashlib.sha256()
    m.update(message)
    h = m.digest()

    curve = Secp256r1()
    # Generate a random k
    k = secrets.randbelow(curve.n)
    # Generate a public key from a private key
    pubKey = curve.g * privKey
    # Calculate r
    r = pubKey.x
    # Calculate s
    s = pow(k, -1, curve.n) * (k + r * privKey)
    # Return signature
    return (r, s)

m = hashlib.sha256()
m.update(b"Hello, world!")
h = m.digest()
print(h)




