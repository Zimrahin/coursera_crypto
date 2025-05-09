from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import click

BLOCK_SIZE = 16  # AES block size in bytes


# Encryption and Decryption intended for a single block of 16 bytes
class AES:
    def __init__(self, key: bytes):
        self.key = key
        self.cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

    def encrypt(self, plaintext: bytes) -> bytes:
        encryptor = self.cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()

    def decrypt(self, ciphertext: bytes) -> bytes:
        decryptor = self.cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


# PKCS padding scheme
def pkcs_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    # Add padding if data is already a multiple of BLOCK_SIZE,
    # because the last byte must be the length of the padding
    if pad_len == 0:
        pad_len = BLOCK_SIZE
    padding = bytes([pad_len] * pad_len)
    return data + padding


def pkcs_unpad(data: bytes) -> bytes:
    if len(data) == 0 or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Invalid padded data length")

    pad_len = data[-1]
    if not 1 <= pad_len <= BLOCK_SIZE:
        raise ValueError(f"Padding value must be between 1 and {BLOCK_SIZE}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS padding")

    return data[:-pad_len]


class CBC:
    def __init__(self, aes: AES):
        self.aes = aes

    def encrypt(self, plaintext: bytes, iv: bytes) -> bytes:
        if iv and len(iv) != BLOCK_SIZE:
            raise ValueError(f"IV must be {BLOCK_SIZE} bytes")
        padded = pkcs_pad(plaintext)
        blocks = [padded[i : i + BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]

        ciphertext = b""
        prev = iv

        for block in blocks:
            # c[i] = E(k, m[i] ⊕ c[i-1]), where c[-1] = IV
            xored = bytes([a ^ b for a, b in zip(block, prev)])
            encrypted = self.aes.encrypt(xored)
            ciphertext += encrypted
            prev = encrypted

        return iv + ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) % BLOCK_SIZE != 0:
            raise ValueError(f"Ciphertext is not a multiple of {BLOCK_SIZE} bytes")
        blocks = [ciphertext[i : i + BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]

        plaintext = b""
        iv = ciphertext[:BLOCK_SIZE]  # First block is the IV
        print(f"IV: {iv.hex()}")
        prev = iv

        for block in blocks:
            # m[i] = D(k, c[i]) ⊕ c[i-1], where c[-1] = IV
            decrypted = self.aes.decrypt(block)
            xored = bytes([a ^ b for a, b in zip(decrypted, prev)])
            plaintext += xored
            prev = block

        return pkcs_unpad(plaintext)[BLOCK_SIZE:]


class CTR:
    def __init__(self, aes: AES):
        self.aes = aes

    def _encrypt_decrypt(self, data: bytes, iv: bytes) -> bytes:
        # Decrypting in CTR mode is the same as encrypting
        if iv and len(iv) != BLOCK_SIZE:
            raise ValueError(f"IV must be {BLOCK_SIZE} bytes")

        # Note that CTR mode does not require padding
        blocks = [data[i : i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
        ciphertext = b""

        for i, block in enumerate(blocks):
            counter = (int.from_bytes(iv, "big") + i).to_bytes(BLOCK_SIZE, "big")
            keystream = self.aes.encrypt(counter)
            ciphertext += bytes([a ^ b for a, b in zip(block, keystream[: len(block)])])

        return ciphertext

    def encrypt(self, plaintext: bytes, iv: bytes) -> bytes:
        return iv + self._encrypt_decrypt(plaintext, iv)

    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) < BLOCK_SIZE:
            raise ValueError("Ciphertext too short, should include IV")

        iv = ciphertext[:BLOCK_SIZE]
        ciphertext_body = ciphertext[BLOCK_SIZE:]

        return self._encrypt_decrypt(ciphertext_body, iv)


@click.command()
@click.option("--test", is_flag=True, help="Run encryption/decryption tests")
def main(test):
    if test:
        key = os.urandom(BLOCK_SIZE)
        iv = os.urandom(BLOCK_SIZE)

        cbc = CBC(AES(key))
        ctr = CTR(AES(key))

        plaintext = b"Hello CBC mode! Testing AES encryption in blocks."
        ciphertext = cbc.encrypt(plaintext, iv)
        decrypted = cbc.decrypt(ciphertext)

        print("Original:", plaintext)
        print("Encrypted:", ciphertext.hex())
        print("Decrypted:", decrypted)

        plaintext = b"Hello CTR mode! Testing AES encryption in blocks."
        ciphertext = ctr.encrypt(plaintext, iv)
        decrypted = ctr.decrypt(ciphertext)

        print("Original:", plaintext)
        print("Encrypted:", ciphertext.hex())
        print("Decrypted:", decrypted)

        return

    # CBC mode encryption/decryption
    cbc_key = bytes.fromhex("140b41b22a29beb4061bda66b6747e14")
    cbc_cipher_1 = bytes.fromhex(
        "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    )
    cbc_cipher_2 = bytes.fromhex(
        "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    )

    cbc = CBC(AES(cbc_key))
    decrypted_1 = cbc.decrypt(cbc_cipher_1)
    decrypted_2 = cbc.decrypt(cbc_cipher_2)
    print("Decrypted 1:", decrypted_1)
    print("Decrypted 2:", decrypted_2)

    # CTE mode encryption/decryption
    ctr_key = bytes.fromhex("36f18357be4dbd77f050515c73fcf9f2")
    ctr_cipher_1 = bytes.fromhex(
        "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    )
    ctr_cipher_2 = bytes.fromhex(
        "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    )

    ctr = CTR(AES(ctr_key))
    decrypted_1 = ctr.decrypt(ctr_cipher_1)
    decrypted_2 = ctr.decrypt(ctr_cipher_2)
    print("Decrypted 1:", decrypted_1)
    print("Decrypted 2:", decrypted_2)


if __name__ == "__main__":
    main()
