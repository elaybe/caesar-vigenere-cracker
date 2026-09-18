import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import pytest

from src.ciphers import (
    caesar_encrypt,
    caesar_decrypt,
    vigenere_encrypt,
    vigenere_decrypt,
)

def test_caesar_encrypt_decrypt():
    plaintext = "Hello, World!"
    shift = 3
    ciphertext = caesar_encrypt(plaintext, shift)
    assert ciphertext == "Khoor, Zruog!"
    assert caesar_decrypt(ciphertext, shift) == plaintext

def test_caesar_full_cycle():
    plaintext = "Information Security 2026"
    assert caesar_encrypt(plaintext, 26) == plaintext
    assert caesar_decrypt(plaintext, 26) == plaintext

def test_vigenere_encrypt_decrypt():
    plaintext = "ATTACKATDAWN"
    key = "LEMON"
    ciphertext = vigenere_encrypt(plaintext, key)
    assert ciphertext == "LXFOPVEFRNHR"
    assert vigenere_decrypt(ciphertext, key) == plaintext

def test_vigenere_with_symbols_and_spaces():
    plaintext = "Secret Message! 123"
    key = "KEY"
    ciphertext = vigenere_encrypt(plaintext, key)
    assert vigenere_decrypt(ciphertext, key) == plaintext