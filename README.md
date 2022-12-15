# cryptography-python-hazmat-rsa-aes

The following program implements the [`pyca/cryptography`](https://cryptography.io) library to do the following:

1. Create a file called `plaintext` that contains `Hello, world!`.
2. Generate an asymmetric RSA-2048 key pair. These keys are wrote to the `keys` directory.
3. Generate a 256-bit key and 128-bit iv for AES-256-CBC symmetric cryptography.
4. Encrypt the symmetric key and iv using the RSA public key.
5. Write the encrypted key and iv to a file called `ciphertext`.
6. Encrypt the contents of `plaintext` and write the resulting ciphertext to the `ciphertext` file. This encryption will add padding if necessary.
7. Read the encrypted symmetric key and iv from the `ciphertext` file. Use the RSA private key to decrypt both of these. Use the decrypted symmetric key and iv to decrypt the main contents of the `ciphertext` file. This decryption will remove adding if necessary.
8. Write the recovered cleartext to a file called `cleartext`

---

This small examples shows how to:

- generate RSA and AES keys
- perform asymmetric encryption and decryption
- perform symmetric encryption and decryption
- reading and writing plaintext, ciphertext, and cleartext
- storing symmetric keys securely with their associated ciphertext

---

## Virtual Environment Setup:

```
python3 -m venv venv
```

```
source venv/bin/activate
```

```
pip3 install cryptography
```
