from collections import Counter
from typing import Tuple, Optional
from .ciphers import caesar_decrypt, vigenere_decrypt

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
    best_shift = 0
    best_score = -float("inf")
    best_plaintext = ""

    clean_text = [c.upper() for c in ciphertext if c.isalpha()]
    n = len(clean_text)
    if n == 0:
        return 0, ciphertext

    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        dec_clean = [c.upper() for c in decrypted if c.isalpha()]
        counts = Counter(dec_clean)
        
        # التقييم الترددي مع تدقيق الأوزان للحروف النادرة
        score = sum((counts.get(letter, 0) / n) * ENGLISH_FREQ[letter] for letter in ENGLISH_FREQ)
        
        # جزاء إضافي إذا ظهرت حروف نادرة بنسب مرتفعة غير منطقية في عينة صغيرة
        rare_penalty = sum(counts.get(rare, 0) for rare in ['Z', 'Q', 'X', 'J']) * 0.005
        score -= rare_penalty

        if score > best_score:
            best_score = score
            best_shift = shift
            best_plaintext = decrypted

    return best_shift, best_plaintext


def calculate_ic(text: str) -> float:
    """
    Computes the Index of Coincidence (IC) for a given text string.
    English text averages ~0.067, while uniform/random distribution is ~0.0385.
    """
    clean_text = [char.upper() for char in text if char.isalpha()]
    n = len(clean_text)
    if n <= 1:
        return 0.0

    counts = Counter(clean_text)
    numerator = sum(count * (count - 1) for count in counts.values())
    denominator = n * (n - 1)

    return numerator / denominator


def find_key_length_ic(ciphertext: str, max_key_length: int = 12) -> int:
    """
    Estimates the unknown Vigenere key length by evaluating the average Index 
    of Coincidence across coset slices for candidate lengths up to max_key_length.
    Selects the length whose average IC is closest to standard English (~0.067).
    """
    clean_text = [c.upper() for c in ciphertext if c.isalpha()]
    if len(clean_text) < 2:
        return 1

    best_length = 1
    best_diff = float("inf")
    target_ic = 0.067

    # حصر البحث في نطاق منطقي لتجنب الوقوع في مضاعفات الطول (مثل 16 بدلاً من 8)
    limit = min(max_key_length, len(clean_text) // 4)
    if limit < 1:
        limit = 1

    for candidate_len in range(1, limit + 1):
        coset_ics = []
        for i in range(candidate_len):
            slice_text = "".join(clean_text[i::candidate_len])
            if len(slice_text) > 1:
                coset_ics.append(calculate_ic(slice_text))

        if coset_ics:
            avg_ic = sum(coset_ics) / len(coset_ics)
            diff = abs(avg_ic - target_ic)
            # نفضل الطول الأصغر عند تقارب الفروق لتجنب مضاعفات الدورة
            if diff < best_diff and (diff < 0.015 or best_diff > 0.02):
                best_diff = diff
                best_length = candidate_len

    return best_length


def break_vigenere(ciphertext: str, key_length: Optional[int] = None) -> Tuple[str, str]:
    """
    Breaks a Vigenere cipher without prior knowledge of the key.
    If key_length is not provided, it is automatically derived via IC analysis.
    The ciphertext is sliced into N independent Caesar streams and cracked individually.
    
    Returns:
        Tuple[str, str]: (recovered_key, decrypted_plaintext)
    """
    if key_length is None or key_length <= 0:
        key_length = find_key_length_ic(ciphertext, max_key_length=12)

    clean_text = [c.upper() for c in ciphertext if c.isalpha()]
    recovered_key_chars = []

    for i in range(key_length):
        slice_text = "".join(clean_text[i::key_length])
        best_shift, _ = break_caesar(slice_text)
        recovered_key_chars.append(chr(best_shift + ord('A')))

    recovered_key = "".join(recovered_key_chars)
    decrypted_text = vigenere_decrypt(ciphertext, recovered_key)

    return recovered_key, decrypted_text