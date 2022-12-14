import os

# https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as padding_rsa

# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.Cipher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# https://cryptography.io/en/latest/hazmat/primitives/padding/#cryptography.hazmat.primitives.padding.ANSIX923
from cryptography.hazmat.primitives import padding as padding_aes


def main():
    # ========================
    # KEY GENERATION AND SETUP
    # ========================

    # write plaintext file
    with open("files/plaintext", "wb") as plaintext:
        plaintext.write(b"Hello, world!")

    # find size of file in bytes
    file_size = os.path.getsize("files/plaintext")

    # generate asymmetric key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    # write private key to file
    with open("keys/private.pem", "wb") as private:
        private.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # write public key to file
    with open("keys/public.pem", "wb") as public:
        public.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    # generate symmetric key and iv
    key = os.urandom(32)
    iv = os.urandom(32)

    # ==========
    # ENCRYPTION
    # ==========

    # write ciphertext file
    with open("files/ciphertext", "wb") as ciphertext:

        # read public key
        with open(f"keys/public.pem", "rb") as public:
            public_key = serialization.load_pem_public_key(
                public.read(), backend=default_backend()
            )

        # encrypt key
        encrypted_key = public_key.encrypt(
            key,
            padding_rsa.OAEP(
                mgf=padding_rsa.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # encrypt iv
        encrypted_iv = public_key.encrypt(
            iv,
            padding_rsa.OAEP(
                mgf=padding_rsa.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # write encrypted key to file
        ciphertext.write(encrypted_key)

        # write encrypted iv to file
        ciphertext.write(encrypted_iv)

        # setup encryption
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv[:16])).encryptor()
        padder = padding_aes.ANSIX923(128).padder()

        # encrypt plaintext file
        with open("files/plaintext", "rb") as plaintext:

            while True:
                bytes_read = plaintext.read(16)

                if not bytes_read:
                    break

                if len(bytes_read) < 16:
                    bytes_read = padder.update(bytes_read) + padder.finalize()

                ciphertext.write(encryptor.update(bytes_read))

    # ==========
    # DECRYPTION
    # ==========

    # read ciphertext
    with open("files/ciphertext", "rb") as ciphertext:

        # read 256 bits (key)
        ciphertext_key = ciphertext.read(256)

        # read 256 bits (iv)
        ciphertext_iv = ciphertext.read(256)

        # read private key
        with open("keys/private.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )

        # decrypt key
        decrypted_key = private_key.decrypt(
            ciphertext_key,
            padding_rsa.OAEP(
                mgf=padding_rsa.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # decrypt iv
        decrypted_iv = private_key.decrypt(
            ciphertext_iv,
            padding_rsa.OAEP(
                mgf=padding_rsa.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # setup encryption
        decryptor = Cipher(
            algorithms.AES(decrypted_key), modes.CBC(decrypted_iv[:16])
        ).decryptor()
        unpadder = padding_aes.ANSIX923(128).unpadder()

        # decrypt ciphertext
        with open("files/cleartext", "wb") as cleartext:
            while True:
                bytes_read = ciphertext.read(16)

                if not bytes_read:
                    break

                clear_bytes = decryptor.update(bytes_read)

                if file_size < 16:
                    clear_bytes = unpadder.update(clear_bytes) + unpadder.finalize()

                cleartext.write(clear_bytes)
                file_size -= 16


if __name__ == "__main__":
    main()
