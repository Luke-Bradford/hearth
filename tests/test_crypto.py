import os
import shutil
import subprocess
import unittest

from hearth import crypto


class AesTest(unittest.TestCase):
    def test_fips197_block(self):
        # FIPS-197 appendix C.1
        rk = crypto._expand_key(bytes(range(16)))
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        ct = crypto.aes_encrypt_block(rk, pt)
        self.assertEqual(ct.hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(crypto.aes_decrypt_block(rk, ct), pt)

    def test_sp800_38a_cbc(self):
        # NIST SP 800-38A F.2.1, first two blocks (no padding involved: check block chaining)
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
        ct = crypto.aes_cbc_encrypt(key, iv, pt)
        self.assertEqual(ct[:32].hex(), "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2")
        self.assertEqual(crypto.aes_cbc_decrypt(key, iv, ct), pt)

    @unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
    def test_matches_openssl_with_padding(self):
        key, iv = b"1234567890123456", b"6543210987654321"
        msg = b'{"operation":"read","params":{"device_mac":"default"}}'
        out = subprocess.run(["openssl", "enc", "-aes-128-cbc", "-K", key.hex(), "-iv", iv.hex()],
                             input=msg, capture_output=True, check=True).stdout
        self.assertEqual(crypto.aes_cbc_encrypt(key, iv, msg), out)
        self.assertEqual(crypto.aes_cbc_decrypt(key, iv, out), msg)

    def test_rejects_bad_padding(self):
        key = iv = bytes(16)
        with self.assertRaises(ValueError):
            crypto.aes_cbc_decrypt(key, iv, os.urandom(32))
        with self.assertRaises(ValueError):
            crypto.aes_cbc_decrypt(key, iv, b"short")


class RsaTest(unittest.TestCase):
    # a small textbook key, big enough for PKCS#1 v1.5 (k=64 bytes): n = p*q, d = e^-1 mod phi
    P = 0xF7E75FDC469067FFDC4E847C51F452DF
    Q = 0xE85CED54AF57E53E092113E62F436F4F

    def test_decrypts_back_to_the_message(self):
        n, e = self.P * self.Q, 65537
        d = pow(e, -1, (self.P - 1) * (self.Q - 1))
        for msg, chunked in ((b"hello deco", False), (b"k=1&i=2&h=" + b"a" * 100, True)):
            hexout = crypto.rsa_encrypt(format(n, "x"), "10001", msg, chunked=chunked)
            k = (n.bit_length() + 7) // 8
            got = b""
            for i in range(0, len(hexout), k * 2):
                block = pow(int(hexout[i:i + k * 2], 16), d, n).to_bytes(k, "big")
                self.assertEqual(block[:2], b"\x00\x02")
                got += block[block.index(b"\x00", 2) + 1:]
            self.assertEqual(got, msg)

    def test_too_long_without_chunking(self):
        n = self.P * self.Q
        with self.assertRaises(ValueError):
            crypto.rsa_encrypt(format(n, "x"), "10001", b"x" * 100)


if __name__ == "__main__":
    unittest.main()
