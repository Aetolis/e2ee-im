import secrets
import hashlib


class Secp256r1(object):
    def __init__(self):
        # Define secp256r1 curve parameters (https://www.secg.org/sec2-v2.pdf)
        self.a = 0x0000000000000000000000000000000000000000000000000000000000000000
        self.b = 0x0000000000000000000000000000000000000000000000000000000000000007
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        self.h = 1
        self.g = Point(
            self,
            0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
            0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
        )

    def generate_private_key(self):
        """Generate a new private key."""
        # Generate a random private key
        privKey = secrets.randbelow(self.n)
        print("privKey", privKey)
        return privKey

    def generate_public_key(self, privKey):
        """Generate a compressed public key from a private key."""
        pubKey = self.g * privKey
        # Compress pubKey
        pubKey_c = "0" + str(2 + pubKey.y % 2) + str(hex(pubKey.x)[2:])
        print("pubKey:", pubKey_c)
        return pubKey_c

    def generate_keypair(self):
        """Generate a new keypair."""
        # Generate a random private key
        privKey = self.generate_private_key()
        # Generate a public key from a private key
        pubKey_c = self.generate_public_key(privKey)
        return privKey, pubKey_c

    @staticmethod
    def mod_sqrt(a, p):
        """Find a quadratic residue (mod p) of a"""
        # Partition p-1 to s * 2^e for an odd s
        s = p - 1
        e = 0
        while s % 2 == 0:
            s //= 2
            e += 1

        # Find some 'n' with a legendre symbol n|p = -1.
        n = 2
        ls = pow(n, (p - 1) // 2, p)
        ls = False if ls == p - 1 else ls
        while ls:
            n += 1
            ls = pow(n, (p - 1) // 2, p)
            ls = False if ls == p - 1 else ls

        x = pow(a, (s + 1) // 2, p)  # a guess of the square root
        b = pow(a, s, p)  # how much we're off with the guess
        g = pow(n, s, p)  # used to update
        r = e  # the exponent

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

    def reconstruct_pubkey(self, pubKey_c):
        """Reconstruct public key from compressed format."""
        x = int("0x" + pubKey_c[2:], 16)
        n = x ** 3 + self.a * x + self.b
        y = self.mod_sqrt(n, self.p)
        if y % 2 != (int(pubKey_c[1]) - 2):
            y = -y % self.p
        return Point(self, x, y)

    def sign(self, privKey, message):
        """Sign message using privKey."""
        # Calculate message hash
        hashBytes = hashlib.sha3_256(message.encode("utf8")).digest()
        h = int.from_bytes(hashBytes, byteorder="big")

        # Generate a random k
        k = secrets.randbelow(self.n)
        # Generate a random point R with k
        R_point = k * self.g
        # Calculate r
        r = R_point.x
        # Calculate s
        s = pow(k, -1, self.n) * (h + r * privKey) % self.n
        # Return signature
        return (r, s)

    def verify(self, message, signature, pubKey_c):
        """Verify a ECDSA signature."""
        r, s = signature

        # Reconstruct pubKey from compressed format
        pubKey = self.reconstruct_pubkey(pubKey_c)

        # Calculate message hash
        hashBytes = hashlib.sha3_256(message.encode("utf8")).digest()
        h = int.from_bytes(hashBytes, byteorder="big")

        # Calculate the modular inverse of signature proof
        s1 = pow(s, -1, self.n) % self.n
        # Reconstruct the random point used in signature
        R_point = (pubKey * (r * s1)) + ((h * s1) * self.g)
        r_ = R_point.x
        # verify signature by comparing given r with r_
        return r_ == r


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


if __name__ == "__main__":
    ecc = Secp256r1()
    privKey, pubKey_c = ecc.generate_keypair()
    (r, s) = ecc.sign(privKey, "message")
    print(ecc.verify("message", (r, s), pubKey_c))
