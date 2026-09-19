import time
from src.ciphers import caesar_encrypt, vigenere_encrypt
from src.attacks import break_caesar, break_vigenere, calculate_ic, find_key_length_ic

def print_separator(title=""):
    print("\n" + "=" * 60)
    if title:
        print(f" [*] {title}")
        print("=" * 60)

def main():
    print_separator("DEMO 1: BREAKING CAESAR CIPHER (BRUTE FORCE & SCORING)")
    
    # 1. Caesar Cipher Demo
    secret_caesar = "Cryptanalysis reveals patterns in legacy substitution ciphers."
    shift_key = 13
    ciphertext_caesar = caesar_encrypt(secret_caesar, shift_key)
    
    print(f"[+] Original Plaintext : {secret_caesar}")
    print(f"[+] Secret Shift Key   : {shift_key}")
    print(f"[+] Encrypted Ciphertext: {ciphertext_caesar}")
    
    # Attack Execution
    start_time = time.perf_counter()
    recovered_shift, recovered_caesar_text = break_caesar(ciphertext_caesar)
    elapsed_caesar = (time.perf_counter() - start_time) * 1000
    
    print("\n[>] Running Automated Cryptanalysis...")
    print(f"[✓] Recovered Shift Key: {recovered_shift} (True Key: {shift_key})")
    print(f"[✓] Recovered Plaintext: {recovered_caesar_text}")
    print(f"[⚡] Execution Time     : {elapsed_caesar:.2f} ms")

    print_separator("DEMO 2: BREAKING VIGENÈRE CIPHER (INDEX OF COINCIDENCE)")
    
    # 2. Vigenère Cipher Demo (Unknown Key & Unknown Length)
    secret_vigenere = (
        "Classical substitution schemes fail to provide confidentiality against ciphertext-only "
        "attacks due to statistical letter frequency leakage and predictable linguistic patterns. "
        "When polyalphabetic ciphers repeat a finite key period across modern transmission channels, "
        "the Index of Coincidence isolates the period length, and coset decomposition completely degrades "
        "the polyalphabetic stream into simple monoalphabetic Caesar systems solvable in linear time."
    )
    
    vigenere_key = "SECURITY"
    ciphertext_vigenere = vigenere_encrypt(secret_vigenere, vigenere_key)
    
    print(f"[+] Original Plaintext : {secret_vigenere[:55]}...")
    print(f"[+] Secret Key (Hidden): {vigenere_key} (Length: {len(vigenere_key)})")
    print(f"[+] Encrypted Payload  : {ciphertext_vigenere[:55]}...")
    
    # Attack Execution (Fully Automated with Zero Prior Knowledge)
    print("\n[>] Step 1: Evaluating Index of Coincidence across candidate lengths...")
    raw_ic = calculate_ic(ciphertext_vigenere)
    print(f"    - Ciphertext Baseline IC: {raw_ic:.4f} (Uniform/Random: ~0.038, English: ~0.067)")
    
    start_time = time.perf_counter()
    detected_length = find_key_length_ic(ciphertext_vigenere, max_key_length=12)
    recovered_vigenere_key, recovered_vigenere_text = break_vigenere(ciphertext_vigenere)
    elapsed_vigenere = (time.perf_counter() - start_time) * 1000
    
    print(f"[✓] Step 2: Auto-Detected Key Length : {detected_length}")
    print(f"[✓] Step 3: Coset Slicing Recovered Key: {recovered_vigenere_key}")
    print(f"[✓] Step 4: Fully Decrypted Text    : {recovered_vigenere_text[:55]}...")
    print(f"[⚡] Cryptanalysis Execution Time   : {elapsed_vigenere:.2f} ms")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    main()