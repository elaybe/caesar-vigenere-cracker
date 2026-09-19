import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.ciphers import caesar_encrypt, vigenere_encrypt
from src.attacks import break_caesar, calculate_ic, break_vigenere

def test_caesar_break():
    message = "Cryptography is the practice and study of secure communication techniques."
    shift = 7
    cipher = caesar_encrypt(message, shift)
    recovered_shift, decrypted = break_caesar(cipher)
    assert recovered_shift == shift
    assert decrypted.lower() == message.lower()

def test_vigenere_ic_calculation():
    english_sample = "Cryptography and network security principles and practice by william stallings."
    ic = calculate_ic(english_sample)
    assert ic > 0.050

def test_break_vigenere():
    plaintext = (
        "The quick brown fox jumps over the lazy dog and provides enough "
        "english text redundant structures to extract polyalphabetic keys easily."
    )
    key = "MATH"
    ciphertext = vigenere_encrypt(plaintext, key)
    
    recovered_key, recovered_plaintext = break_vigenere(ciphertext, key_length=len(key))
    assert recovered_key.upper() == key.upper()
    assert recovered_plaintext.lower() == plaintext.lower()