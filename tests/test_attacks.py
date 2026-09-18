import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from src.ciphers import caesar_encrypt, vigenere_encrypt
from src.attacks import break_caesar, calculate_ic, break_vigenere

def test_break_caesar():
    secret_text = "This is a secret message that needs to be long enough for frequency analysis."
    shift = 7
    ciphertext = caesar_encrypt(secret_text, shift)
    
    recovered_shift, recovered_plaintext = break_caesar(ciphertext)
    assert recovered_shift == shift
    assert recovered_plaintext.lower() == secret_text.lower()

def test_vigenere_ic_calculation():
    # النص العشوائي له IC منخفض (~0.038)، بينما النص الإنجليزي العادي له IC أعلى (~0.067)
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