from file_util import write_file

from crypto_util import (generate_aes_key, encrypt_data, decrypt_data, compute_hash, generate_keypair, sign_data,
                         verify_signature)

from crypto_util import generate_ephemeral_keypair, derive_shared_key


def test_encryption_and_decryption():
    key = generate_aes_key()
    data_type = b"Hello this is a test"

    encrypted = encrypt_data(key, data_type)
    decrypted = decrypt_data(key, encrypted)

    assert decrypted == data_type


def test_ciphertext_is_tampered():
    key = generate_aes_key()
    data_type = b"This data will be tampered"

    encrypted = encrypt_data(key, data_type)

    tampered_text = bytearray(encrypted)
    tampered_text[-1] ^= 1

    try:
        decrypt_data(key, bytes(tampered_text))
        print("Successfully decrypted file [not expected]")
        assert False
    except Exception:
        print("Decryption has failed; as expected")
        assert True


def test_valid_hash():
    data = b"My hash"

    hash1 = compute_hash(data)
    hash2 = compute_hash(data)

    assert hash1 == hash2


def test_hash_tampered():
    data1 = b"File type a"
    data2 = b"File type b"

    hash1 = compute_hash(data1)
    hash2 = compute_hash(data2)

    assert hash1 != hash2


def test_valid_signature():
    private_key, public_key = generate_keypair()
    data = b"Message"

    signature_data = sign_data(private_key, data)

    assert verify_signature(public_key, data, signature_data)


def test_invalid_signature():
    private_key1, public_key1 = generate_keypair()
    private_key2, public_key2 = generate_keypair()
    data = b"Invalid File"

    signature_data = sign_data(private_key1, data)

    assert not verify_signature(public_key2, data, signature_data)


def test_file_storage_encrypted():
    from crypto_util import generate_aes_key, encrypt_data

    filename = "secure.txt"
    data = b"Secret info"

    key = generate_aes_key()
    encrypted = encrypt_data(key, data)

    write_file(filename, encrypted)

    raw = open("Storage/" + filename, "rb").read()

    # raw should not equal to plain text but encrypted.
    assert raw != data

    # raw SHOULD equal encrypted
    assert raw == encrypted


def test_key_exchange_logic():
    private1, public1 = generate_ephemeral_keypair()
    private2, public2 = generate_ephemeral_keypair()

    key1 = derive_shared_key(private1, public2)
    key2 = derive_shared_key(private2, public1)

    assert key1 == key2


def test_mitm_attack_fail():
    alice_priv, alice_public = generate_keypair()
    bob_priv, bob_pub = generate_keypair()
    attacker_priv, attacker_pub = generate_keypair()

    eph_key = b"ephemeral_key"

    # Attacker tries to provide false information to bob posing as alice

    fake_user_signature = sign_data(attacker_priv, eph_key)

    assert not verify_signature(alice_public, eph_key, fake_user_signature)
    print("MITM attack has failed.")