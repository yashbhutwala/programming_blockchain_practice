from binascii import unhexlify
from unittest import TestCase

from helper import (
    decode_base58,
    encode_base58_checksum
)

class HelperTest(TestCase):

    def test_base58(self):
        addr = '1BenRpVUFK65JFWcQSuHnJKzc4M8ZP8Eqa'
        h160 = unhexlify('0074d691da1574e6b3c192ecfb52cc8984ee7b6c56')
        self.assertEqual(decode_base58(addr), h160)
        self.assertRaises(ValueError, decode_base58, addr+'1')
        got = encode_base58_checksum(h160)
        self.assertEqual(got, addr)
        wif = '5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf'
        want = unhexlify('800000000000000000000000000000000000000000000000000000000000000001')
        self.assertEqual(decode_base58(wif, num_bytes=38, strip_leading_zeros=True), want)