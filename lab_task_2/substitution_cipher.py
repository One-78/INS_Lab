
from string import ascii_lowercase
from collections import Counter

alphabet = ascii_lowercase
alphabet_size = 26


print(f"\nAlphabet: {alphabet}")
print(f"Alphabet Size: {alphabet_size}\n")

# Mapping the frequency distribution of the characters (English language)
freq = {
    'a': 8.05, 'e': 12.22, 'i': 6.28, 'm': 2.33, 'q': 0.06, 'u': 2.92, 'y': 2.04,
    'b': 1.67, 'f': 2.14, 'j': 0.19, 'n': 6.95, 'r': 5.29, 'v': 0.82, 'z': 0.06,
    'c': 2.23, 'g': 2.30, 'k': 0.95, 'o': 7.63, 's': 6.02, 'w': 2.60,
    'd': 5.10, 'h': 6.62, 'l': 4.08, 'p': 1.66, 't': 9.67, 'x': 0.11
}

# Implementing the chi squared scoring method
def score(text: str) -> float:
    counter = Counter(c for c in text if c in alphabet)
    total = sum(counter.values())
    if total == 0:
        return float('inf')
    chi_sq = sum((counter.get(c, 0) - freq[c] * total / 100)**2 / (freq[c] * total / 100) for c in alphabet)
    return chi_sq

# Decrypt text using a substitution key mapping
def decrypt_text(cipher: str, key_mapping: dict) -> str:
    decrypted = ''
    for text in cipher:
        if text in alphabet:
            decrypted += key_mapping.get(text, text)
    return decrypted

# Get frequency sorted letters from text
def get_sorted_by_frequency(text: str) -> list:
    counter = Counter(c for c in text if c in alphabet)
    sorted_letters = sorted(counter.items(), key=lambda x: x[1], reverse=True)
    return [letter for letter, count in sorted_letters]

# Get frequency sorted letters from standard distribution
def get_standard_frequency_order() -> list:
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    return [letter for letter, frequency in sorted_freq]

all_keys = []

# Attack substitution cipher using frequency analysis with hill climbing
def attack_cipher(cipher: str, max_iterations: int = 1000) -> tuple:
    lowest_difference = float('inf')
    desired_key = {}

    # Get cipher letter frequencies
    cipher_freq_order = get_sorted_by_frequency(cipher)
    standard_freq_order = get_standard_frequency_order()

    # Create initial mapping based on frequency matching
    current_mapping = {}
    for i in range(len(cipher_freq_order)):
        if i < len(standard_freq_order):
            current_mapping[cipher_freq_order[i]] = standard_freq_order[i]

    # Fill remaining letters that don't appear in cipher
    used_letters = set(current_mapping.values())
    unused_cipher = [c for c in alphabet if c not in current_mapping]
    unused_standard = [c for c in alphabet if c not in used_letters]

    for i in range(len(unused_cipher)):
        if i < len(unused_standard):
            current_mapping[unused_cipher[i]] = unused_standard[i]

    # Test initial mapping
    decrypted = decrypt_text(cipher, current_mapping)
    decrypt_score = score(decrypted)

    if decrypt_score < lowest_difference:
        lowest_difference = decrypt_score
        desired_key = current_mapping.copy()
        all_keys.append(desired_key.copy())
        print(f"The new lowest difference {lowest_difference}\n")
        print(f"The new desired key mapping: {desired_key}\n")
        print("-" * 80 + "\n\n")

    # Hill climbing with iterations
    cipher_letters = list(current_mapping.keys())
    no_improvement_count = 0

    for iteration in range(max_iterations):
        improved = False

        # Try swapping every pair of cipher letter mappings
        for i in range(len(cipher_letters)):
            for j in range(i + 1, len(cipher_letters)):
                letter1 = cipher_letters[i]
                letter2 = cipher_letters[j]

                # Create test mapping with swapped values
                test_mapping = current_mapping.copy()
                test_mapping[letter1], test_mapping[letter2] = test_mapping[letter2], test_mapping[letter1]

                # Decrypt and score
                decrypted = decrypt_text(cipher, test_mapping)
                decrypt_score = score(decrypted)

                # If this swap improves the score, keep it
                if decrypt_score < lowest_difference:
                    lowest_difference = decrypt_score
                    desired_key = test_mapping.copy()
                    current_mapping = test_mapping.copy()
                    all_keys.append(desired_key.copy())
                    improved = True
                    no_improvement_count = 0
                    print(f"Iteration {iteration + 1}: The new lowest difference {lowest_difference}\n")
                    print(f"The new desired key mapping: {desired_key}\n")
                    print("-" * 80 + "\n\n")
                    break

            if improved:
                break

        # If no improvement found in this iteration
        if not improved:
            no_improvement_count += 1
            # Stop if no improvement for 10 consecutive iterations
            if no_improvement_count >= 10:
                print(f"No improvement for 10 iterations. Stopping at iteration {iteration + 1}.\n")
                break

    final_decrypted = decrypt_text(cipher, desired_key)
    return final_decrypted, desired_key


# Test with a substitution cipher
input1 = 'af p xpkcaqvnpk pfg, af ipqe qpri, gauuikifc tpw, ceiri udvk tiki afgarxifrphni cd eao- -wvmd popkwn, hiqpvri du ear jvaql vfgikrcpfgafm du cei xkafqaxnir du xrwqedearcdkw pfg  du ear aopmafpcasi xkdhafmr afcd fit pkipr. ac tpr qdoudkcafm cd lfdt cepc au pfwceafm  epxxifig cd ringdf eaorinu hiudki cei opceiopcaqr du cei uaing qdvng hi qdoxnicinw tdklig dvc- -pfg edt rndtnw ac xkdqiigig, pfg edt odvfcpafdvr cei dhrcpqnir--ceiki tdvng pc niprc kiopaf dfi  mddg oafg cepc tdvng qdfcafvi cei kiripkqe'
first_encrypt, first_key = attack_cipher(input1)
print(f"\nFinal decrypted text: {first_encrypt}")
print(f"\nFinal key mapping: {first_key}")


input2 = 'aceah toz puvg vcdl omj puvg yudqecov omj loj auum klu thmjuv hs klu zlcvu shv zcbkg guovz upuv zcmdu lcz vuwovroaeu jczoyyuovomdu omj qmubyudkuj vukqvm klu vcdluz lu loj avhqnlk aodr svhw lcz kvopuez loj mht audhwu o ehdoe eunumj omj ck toz yhyqeoveg auecupuj tlokupuv klu hej sher wcnlk zog klok klu lcee ok aon umj toz sqee hs kqmmuez zkqssuj tckl kvuozqvu omj cs klok toz mhk umhqnl shv sowu kluvu toz oezh lcz yvhehmnuj pcnhqv kh wovpue ok kcwu thvu hm aqk ck zuuwuj kh lopu eckkeu ussudk hm wv aonncmz ok mcmukg lu toz wqdl klu zowu oz ok scskg ok mcmukg mcmu klug aunom kh doee lcw tuee yvuzuvpuj aqk qmdlomnuj thqej lopu auum muovuv klu wovr kluvu tuvu zhwu klok zlhhr klucv luojz omj klhqnlk klcz toz khh wqdl hs o nhhj klcmn ck zuuwuj qmsocv klok omghmu zlhqej yhzzuzz oyyovumkeg yuvyukqoe ghqkl oz tuee oz vuyqkujeg cmubloqzkcaeu tuoekl ck tcee lopu kh au yocj shv klug zocj ck czm k mokqvoe omj kvhqaeu tcee dhwu hs ck aqk zh sov kvhqaeu loj mhk dhwu omj oz wv aonncmz toz numuvhqz tckl lcz whmug whzk yuhyeu tuvu tceecmn kh shvncpu lcw lcz hjjckcuz omj lcz nhhj shvkqmu lu vuwocmuj hm pczckcmn kuvwz tckl lcz vueokcpuz ubduyk hs dhqvzu klu zodrpceeu aonncmzuz omj lu loj womg juphkuj ojwcvuvz owhmn klu lhaackz hs yhhv omj qmcwyhvkomk sowcecuz aqk lu loj mh dehzu svcumjz qmkce zhwu hs lcz ghqmnuv dhqzcmz aunom kh nvht qy klu uejuzk hs kluzu omj aceoh z sophqvcku toz ghqmn svhjh aonncmz tlum aceah toz mcmukg mcmu lu ojhykuj svhjh oz lcz lucv omj avhqnlk lcw kh ecpu ok aon umj omj klu lhyuz hs klu zodrpceeu aonncmzuz tuvu scmoeeg jozluj aceah omj svhjh loyyumuj kh lopu klu zowu acvkljog zuykuwauv ktumkg zudhmj ghq loj aukkuv dhwu omj ecpu luvu svhjh wg eoj zocj aceah hmu jog omj klum tu dom dueuavoku hqv acvkljog yovkcuz dhwshvkoaeg khnukluv ok klok kcwu svhjh toz zkcee cm lcz ktuumz oz klu lhaackz doeeuj klu cvvuzyhmzcaeu ktumkcuz auktuum dlcejlhhj omj dhwcmn hs onu ok klcvkg klvuu'
second_encrypt, second_key = attack_cipher(input2)
print(f"\nFinal decrypted text: {second_encrypt}")
print(f"\nFinal key mapping: {second_key}")
