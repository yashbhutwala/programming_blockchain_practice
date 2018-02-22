from binascii import hexlify
from io import BytesIO
from random import randint

from helper import (decode_base58, double_sha256, encode_base58,
                    encode_base58_checksum, hash160)


class FieldElement:

    def __init__(self, num, prime):
        self.num = num
        self.prime = prime
        if self.num >= self.prime or self.num < 0:
            error = 'Num {} not in field range 0 to {}'.format(
                self.num, self.prime - 1)
            raise RuntimeError(error)

    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other):
        if other is None:
            return True
        return self.num != other.num or self.prime != other.prime

    def __repr__(self):
        return 'FieldElement_{}({})'.format(self.prime, self.num)

    def __add__(self, other):
        """
        self.num and other.num are the actual values
        self.prime is what you'll need to mod against
        You need to return an element of the same class
        use: self.__class__(num, prime)
        """
        if self.prime != other.prime:
            raise RuntimeError('Primes must be the same')
        prime = self.prime
        num = (self.num + other.num) % prime
        return self.__class__(num, prime)

    def __sub__(self, other):
        """
        self.num and other.num are the actual values
        self.prime is what you'll need to mod against
        You need to return an element of the same class
        use: self.__class__(num, prime)
        """
        if self.prime != other.prime:
            raise RuntimeError('Primes must be the same')
        prime = self.prime
        num = (self.num - other.num) % prime
        return self.__class__(num, prime)

    def __mul__(self, other):
        """
        self.num and other.num are the actual values
        self.prime is what you'll need to mod against
        You need to return an element of the same class
        use: self.__class__(num, prime)
        """
        if self.prime != other.prime:
            raise RuntimeError('Primes must be the same')
        prime = self.prime
        num = (self.num * other.num) % prime
        return self.__class__(num, prime)

    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        return self.__class__(num=num, prime=self.prime)

    def __pow__(self, n):
        """
        remember fermat's little theorem:
        self.num**(p-1) % p == 1
        you might want to use % operator on n
        """
        prime = self.prime
        num = pow(self.num, n % (prime - 1), prime)
        return self.__class__(num, prime)

    def __truediv__(self, other):
        """
        use fermat's little theorem:
        self.num**(p-1) % p == 1
        this means:
        1/n == pow(n, p-2, p)
        You need to return an element of the same class
        use: self.__class__(num, prime)
        """
        if self.prime != other.prime:
            raise RuntimeError('Primes must be the same')
        prime = self.prime
        num = (self.num * pow(other.num, prime - 2, prime)) % prime
        return self.__class__(num, prime)


class Point:

    def __init__(self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        # Exercise 5.1: x being None and y being None represents the point at infinity
        # Exercise 5.1: Check for that here since the equation below won't make sense
        # Exercise 5.1: with None values for both.
        if self.x is None and self.y is None:
            return

        # Exercise 4.2: make sure that the elliptic curve equation is satisfied
        # y**2 == x**3 + a*x + b
        # if not, throw a RuntimeError
        if self.y**2 != self.x**3 + a * x + b:
            raise RuntimeError(
                '({}, {}) is not on the curve'.format(self.x, self.y))

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y \
            and self.a == other.a and self.b == other.b

    def __ne__(self, other):
        return self.x != other.x or self.y != other.y \
            or self.a != other.a or self.b != other.b

    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        return 'Point({},{})'.format(self.x, self.y)

    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise RuntimeError(
                'Points {}, {} are not on the same curve'.format(self, other))

        # Case 0.0: self is the point at infinity, return other
        if self.x == None:
            return other

        # Case 0.1: other is the point at infinity, return self
        if other.x == None:
            return self

        # Case 1: self.x == other.x, self.y != other.y
        if self.x == other.x and self.y != other.y:
            # Result is point at infinity
            x3 = y3 = None

        # Case 2: self.x != other.x
        elif self.x != other.x:
            # Formula (x3,y3)==(x1,y1)+(x2,y2)
            # s=(y2-y1)/(x2-x1)
            # x3=s**2-x1-x2
            # y3=s*(x1-x3)-y1
            s = (other.y - self.y) / (other.x - self.x)
            x3 = s**2 - self.x - other.x
            y3 = s * (self.x - x3) - self.y

        # Case 3: self.x == other.x, self.y == other.y
        else:
            # Formula (x3,y3)=(x1,y1)+(x1,y1)
            # s=(3*x1**2+a)/(2*y1)
            # x3=s**2-2*x1
            # y3=s*(x1-x3)-y1
            s = (3 * self.x**2 + self.a) / (2 * self.y)
            x3 = s**2 - 2 * self.x
            y3 = s * (self.x - x3) - self.y

        # Remember to return an instance of this class:
        # self.__class__(x, y, a, b)
        return self.__class__(x3, y3, self.a, self.b)

    def __rmul__(self, coefficient):
        # rmul calculates coefficient * self
        # implement the naive way:
        # start product from 0 (point at infinity)
        # use: self.__class__(None, None, a, b)
        product = self.__class__(None, None, self.a, self.b)
        # loop coefficient times
        # use: for _ in range(coefficient):
        for _ in range(coefficient):
            # keep adding self over and over
            product += self
        # return the product
        return product
        # Extra Credit:
        # a more advanced technique uses point doubling
        # find the binary representation of coefficient
        # keep doubling the point and if the bit is there for coefficient
        # add the current.
        # remember to return an instance of the class


A = 0
B = 7
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class S256Field(FieldElement):

    def __init__(self, num, prime=None):
        super().__init__(num=num, prime=P)

    def hex(self):
        return '{:x}'.format(self.num).zfill(64)

    def __repr__(self):
        return self.hex()


class S256Point(Point):
    bits = 256

    def __init__(self, x, y, a=None, b=None):
        a, b = S256Field(A), S256Field(B)
        if x is None:
            super().__init__(x=None, y=None, a=a, b=b)
        elif type(x) == int:
            super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)

    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        else:
            return 'Point({},{})'.format(self.x, self.y)

    def __rmul__(self, coefficient):
        # current will undergo binary expansion
        current = self
        # result is what we return, starts at 0
        result = S256Point(None, None)
        # we double 256 times and add where there is a 1 in the binary
        # representation of coefficient
        for _ in range(self.bits):
            if coefficient & 1:
                result += current
            current += current
            # we shift the coefficient to the right
            coefficient >>= 1
        return result

    def sec(self, compressed=True):
        # returns the binary version of the sec format, NOT hex
        # if compressed, starts with b'\x02' if self.y.num is even, b'\x03' if self.y is odd
        # then self.x.num
        # remember, you have to convert self.x.num/self.y.num to binary (some_integer.to_bytes(32, 'big'))
        if compressed:
            if self.y.num % 2 == 0:
                return b'\x02' + self.x.num.to_bytes(32, 'big')
            else:
                return b'\x03' + self.x.num.to_bytes(32, 'big')
        else:
            # if non-compressed, starts with b'\x04' followod by self.x and then self.y
            return b'\x04' + self.x.num.to_bytes(32, 'big') + self.y.num.to_bytes(32, 'big')

    def address(self, compressed=True, testnet=False):
        '''Returns the address string'''
        # get the sec
        sec = self.sec(compressed)
        # hash160 the sec
        h160 = hash160(sec)
        # raw is hash 160 prepended w/ b'\x00' for mainnet, b'\x6f' for testnet
        if testnet:
            prefix = b'\x6f'
        else:
            prefix = b'\x00'
        raw = prefix + h160
        # checksum is first 4 bytes of double_sha256 of raw
        checksum = double_sha256(raw)[:4]
        # encode_base58 the raw + checksum
        address = encode_base58(raw+checksum)
        # return as a string, you can use .decode('ascii') to do this.
        return address.decode('ascii')
        # return encode_base58_checksum(raw)

    def verify(self, z, sig):
        # remember sig.r and sig.s are the main things we're checking
        # remember 1/s = pow(s, N-2, N)
        s_inv = pow(sig.s, N-2, N)
        # u = z / s
        u = z * s_inv % N
        # v = r / s
        v = sig.r * s_inv % N
        # u*G + v*P should have as the x coordinate, r
        total = u*G + v*self
        return total.x.num == sig.r


G = S256Point(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)


class Signature:

    def __init__(self, r, s):
        self.r = r
        self.s = s

    def __repr__(self):
        return 'Signature({:x},{:x})'.format(self.r, self.s)

    def der(self):
        rbin = self.r.to_bytes(32, byteorder='big')
        # if rbin has a high bit, add a 00
        if rbin[0] > 128:
            rbin = b'\x00' + rbin
        result = bytes([2, len(rbin)]) + rbin
        sbin = self.s.to_bytes(32, byteorder='big')
        # if sbin has a high bit, add a 00
        if sbin[0] > 128:
            sbin = b'\x00' + sbin
        result += bytes([2, len(sbin)]) + sbin
        return bytes([0x30, len(result)]) + result

    @classmethod
    def parse(cls, signature_bin):
        s = BytesIO(signature_bin)
        compound = s.read(1)[0]
        if compound != 0x30:
            raise RuntimeError("Bad Signature")
        length = s.read(1)[0]
        if length + 2 != len(signature_bin):
            raise RuntimeError("Bad Signature Length")
        marker = s.read(1)[0]
        if marker != 0x02:
            raise RuntimeError("Bad Signature")
        rlength = s.read(1)[0]
        r = int(hexlify(s.read(rlength)), 16)
        marker = s.read(1)[0]
        if marker != 0x02:
            raise RuntimeError("Bad Signature")
        slength = s.read(1)[0]
        s = int(hexlify(s.read(slength)), 16)
        if len(signature_bin) != 6 + rlength + slength:
            raise RuntimeError("Signature too long")
        return cls(r, s)


class PrivateKey:

    def __init__(self, secret):
        self.secret = secret
        self.point = secret*G

    def hex(self):
        return '{:x}'.format(self.secret).zfill(64)

    def sign(self, z):
        # we need a random number k: randint(0, 2**256)
        k = randint(0, 2**256)
        # r is the x coordinate of the resulting point k*G
        r = (k*G).x.num
        # remember 1/k = pow(k, N-2, N)
        k_inv = pow(k, N-2, N)
        # s = (z+r*secret) / k
        s = (z + r*self.secret) * k_inv % N
        # return an instance of Signature:
        # Signature(r, s)
        return Signature(r, s)
