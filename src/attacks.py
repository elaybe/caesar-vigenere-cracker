from collections import Counter
from typing import Tuple
from ciphers import caesar_decrypt, vigenere_decrypt

# Approximate frequency distribution of letters in the English language
ENGLISH_FREQ = {
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253, 'E': 0.12702,
    'F': 0.02228, 'G': 0.02015, 'H': 0.06094, 'I': 0.06966, 'J': 0.00153,
    'K': 0.00772, 'L': 0.04025, 'M': 0.02406, 'N': 0.06749, 'O': 0.07507,
    'P': 0.01929, 'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
    'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150, 'Y': 0.01974,
    'Z': 0.00074
}


def score_text(text: str) -> float:
    """
    Evaluates how closely the letter frequencies of the given text 
    match standard English frequencies using a dot-product metric.
    """
    clean_text = [char.upper() for char in text if char.isalpha()]
    if not clean_text:
        return 0.0

    counts = Counter(clean_text)
    total_chars = len(clean_text)

    # Compute dot-product score against standard English frequencies
    return sum((counts.get(char, 0) / total_chars) * freq for char, freq in ENGLISH_FREQ.items())


def break_caesar(ciphertext: str) -> Tuple[int, str]:
    """
    Breaks a Caesar cipher using brute-force search across all 26 possible shifts 
    and selects the shift with the highest English frequency score.
    
    Returns:
        Tuple[int, str]: (best_shift, decrypted_plaintext)
    """
    best_shift = 0
    best_score = -1.0
    best_plaintext = ""

    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        current_score = score_text(decrypted)

        if current_score > best_score:
            best_score = current_score
            best_shift = shift
            best_plaintext = decrypted

    return best_shift, best_plaintext


def break_vigenere(ciphertext: str, key_length: int) -> Tuple[str, str]:
    """
    Breaks a Vigenere cipher given a known key length by slicing the ciphertext 
    into N independent Caesar ciphers and cracking each position individually.
    
    Returns:
        Tuple[str, str]: (recovered_key, decrypted_plaintext)
    """
    clean_text = [c.upper() for c in ciphertext if c.isalpha()]
    recovered_key_chars = []

    for i in range(key_length):
        # Extract the slice encrypted by the same key character position
        slice_text = "".join(clean_text[i::key_length])
        best_shift, _ = break_caesar(slice_text)
        recovered_key_chars.append(chr(best_shift + ord('A')))

    recovered_key = "".join(recovered_key_chars)
    decrypted_text = vigenere_decrypt(ciphertext, recovered_key)

    return recovered_key, decrypted_text
