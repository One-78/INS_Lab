
## Lab Task 1 : breaking the classic cipher

from string import ascii_lowercase
from collections import Counter

alphabet = ascii_lowercase
print(alphabet)

alphabet_size = 26
print(alphabet_size)

## Mapping the frequency distribution of the characters

freq = {
    'a': 8.05, 'e': 12.22, 'i': 6.28, 'm': 2.33, 'q': 0.06, 'u': 2.92, 'y': 2.04,
    'b': 1.67, 'f': 2.14, 'j': 0.19, 'n': 6.95, 'r': 5.29, 'v': 0.82, 'z': 0.06,
    'c': 2.23, 'g': 2.30, 'k': 0.95, 'o': 7.63, 's': 6.02, 'w': 2.60,
    'd': 5.10, 'h': 6.62, 'l': 4.08, 'p': 1.66, 't': 9.67, 'x': 0.11
}
print(freq)

## Implementing the chi squared scoring method to see how close the frequency distribution of character of decrypt form with the given distribution.Lower the score better

def score(text : str) -> float:
  counter = Counter(c for c in text if c in alphabet)
  total   = sum(counter.values()) # Chi squared method
  if total == 0:
    return float('inf')

  chi_sq = sum((counter.get(c , 0) - freq[c] * total / 100)**2 / (freq[c] * total / 100) for c in alphabet)
  return chi_sq

def decrypt_text(cipher : str , key : int) -> str:
  decrypted = ''
  for text in cipher:
    if text in alphabet:
      text_index = alphabet.index(text)
      decrypted_index = (text_index - key) % alphabet_size
      decrypted += alphabet[decrypted_index]
  return decrypted

all_keys=[]
def attack_cipher(cipher : str) -> str:
  lowest_difference = float('inf')
  desired_key = 0
  for key in range(1 , alphabet_size):
    decrypted = decrypt_text(cipher , key)
    decrypt_score = score(decrypted)
    if decrypt_score < lowest_difference:
      lowest_difference = decrypt_score
      desired_key = key
      all_keys.append(key)
      print(f"The new lowest difference {lowest_difference}\n")
      print(f"The new desired key {desired_key}\n")
      print("-" * 80 + "\n\n")
  return decrypted , desired_key

input1 = "odroboewscdrolocdcwkbdmyxdbkmdzvkdpybwyeddrobo"

first_encrypt , first_key = attack_cipher(input1)

print(first_encrypt)
print(first_key)
