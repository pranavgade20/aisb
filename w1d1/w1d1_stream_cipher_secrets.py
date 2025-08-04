def intercept_messages(encrypt):
    message1 = b"""A linear congruential generator is one of the oldest and most studied pseudorandom number generators in computer science. Despite its simplicity and speed, it should never be used for cryptographic purposes due to its predictability."""

    message2 = b"""The security of stream ciphers depends critically on the quality of their keystream generators. When weak PRNGs are used, the entire cryptosystem becomes vulnerable to various attacks including state recovery and prediction."""

    # Encrypt both with the same key
    SECRET_SEED = 42424242
    ciphertext1 = encrypt(SECRET_SEED, message1)
    ciphertext2 = encrypt(SECRET_SEED, message2)

    return ciphertext1, ciphertext2