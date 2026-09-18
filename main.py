def main():
    # 1. اختبار شيفرة قيصر (Caesar Cipher)
    caesar_text = "The quick brown fox jumps over the lazy dog."
    caesar_shift = 7

    caesar_encrypted = caesar_encrypt(caesar_text, caesar_shift)
    caesar_decrypted = caesar_decrypt(caesar_encrypted, caesar_shift)
    detected_shift, cracked_caesar = break_caesar(caesar_encrypted)

    print("--- Caesar Cipher ---")
    print(f"Original:  {caesar_text}")
    print(f"Encrypted: {caesar_encrypted}")
    print(f"Decrypted: {caesar_decrypted}")
    print(f"Cracked Shift: {detected_shift}")
    print(f"Cracked Text:  {cracked_caesar}\n")

    # 2. اختبار شيفرة فيجينير (Vigenère Cipher)
    vigenere_text = (
        "Cryptography is the practice and study of techniques for secure communication "
        "in the presence of adversarial third parties."
    )
    vigenere_key = "KEY"

    vigenere_encrypted = vigenere_encrypt(vigenere_text, vigenere_key)
    vigenere_decrypted = vigenere_decrypt(vigenere_encrypted, vigenere_key)
    recovered_key, cracked_vigenere = break_vigenere(vigenere_encrypted, key_length=len(vigenere_key))

    print("--- Vigenere Cipher ---")
    print(f"Original:      {vigenere_text}")
    print(f"Encrypted:     {vigenere_encrypted}")
    print(f"Decrypted:     {vigenere_decrypted}")
    print(f"Recovered Key: {recovered_key}")
    print(f"Cracked Text:  {cracked_vigenere}")


if __name__ == "__main__":
    main()