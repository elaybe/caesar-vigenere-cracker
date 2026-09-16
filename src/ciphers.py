#Caesar Cipher
def caesar_encrypt(plaintext: str, shift: int) -> str:
    """
    Encrypts a given plaintext using the Caesar cipher with a specified shift.
    """
    ciphertext = []
    shift = shift % 26
    
    for char in plaintext:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            shifted_char = chr((ord(char) - start + shift) % 26 + start)
            ciphertext.append(shifted_char)
        else:
            ciphertext.append(char)
            
    return "".join(ciphertext)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """
    Decrypts a ciphertext encrypted with the Caesar cipher using the specified shift.
    """
    return caesar_encrypt(ciphertext, -shift)



#Vigenere Cipher
def vigenere_encrypt(plaintext: str, key: str) -> str:
    """
    Encrypts plaintext using the Vigenère cipher with a given keyword.
    """
    ciphertext = []
    key = key.upper()
    key_index = 0
    
    for char in plaintext:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            shifted_char = chr((ord(char) - start + shift) % 26 + start)
            ciphertext.append(shifted_char)
            key_index += 1
        else:
            ciphertext.append(char)
            
    return "".join(ciphertext)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """
    Decrypts ciphertext encrypted with the Vigenère cipher using the given key.
    """
    decrypted_text = []
    key = key.upper()
    key_index = 0
    
    for char in ciphertext:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            shifted_char = chr((ord(char) - start - shift) % 26 + start)
            decrypted_text.append(shifted_char)
            key_index += 1
        else:
            decrypted_text.append(char)
            
    return "".join(decrypted_text)