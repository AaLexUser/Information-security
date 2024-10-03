import argparse
from collections import Counter
from caesar_cipher import CaesarCipher
from frequency_analysis import FrequencyAnalyzer
from tabulate import tabulate


def read_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as file:
        return file.read()


def write_file(filepath, content):
    with open(filepath, 'w', encoding='utf-8') as file:
        file.write(content)


def encrypt_file(input_path, output_path, shift):
    cipher = CaesarCipher(shift)
    plaintext = read_file(input_path)
    ciphertext = cipher.encrypt(plaintext)
    write_file(output_path, ciphertext)
    print(f"Файл зашифрован и сохранён как {output_path}")


def decrypt_file(input_path, output_path, shift):
    cipher = CaesarCipher(shift)
    ciphertext = read_file(input_path)
    plaintext = cipher.decrypt(ciphertext)
    write_file(output_path, plaintext)
    print(f"Файл дешифрован и сохранён как {output_path}")


def print_frequency_table(freq: Counter):
    print("Частотный анализ зашифрованного текста:")
    # Normalize frequencies
    total = sum(freq.values())
    freq_percent = {char: round((count / total) * 100, 3) for char, count in freq.items()}
    sorted_freq = freq.most_common()
    print(tabulate([(char, count, freq_percent[char]) for char, count in sorted_freq],
          headers=['Символ', 'Количество', 'Частота'], tablefmt='grid'))


def frequency_detect_shift(input_path):
    analyzer = FrequencyAnalyzer()
    ciphertext = read_file(input_path)
    freq = analyzer.analyze(ciphertext)
    print_frequency_table(freq)

    # Попытка дешифровки методом частотного анализа
    english_shift, russian_shift = analyzer.detect_shift(ciphertext)
    print("\nПопытка дешифровки с использованием частотного анализа:")
    print(f"Наиболее вероятный сдвиг для английского алфавита: {english_shift}")
    print(f"Наиболее вероятный сдвиг для русского алфавита: {russian_shift}")
    # Дешифровка с найденным сдвигом для каждого алфавита
    cipher_english = CaesarCipher(english_shift)
    cipher_russian = CaesarCipher(russian_shift)
    decrypted_text_english = cipher_english.decrypt(ciphertext)
    decrypted_text_russian = cipher_russian.decrypt(ciphertext)
    print(f"Расшифрованный текст (английский сдвиг):\n{decrypted_text_english}")
    print(f"Расшифрованный текст (русский сдвиг):\n{decrypted_text_russian}")


def frequency_analysis(input_path, keywords_file):
    analyzer = FrequencyAnalyzer(keywords_file)
    ciphertext = read_file(input_path)
    freq = analyzer.analyze(ciphertext)
    print_frequency_table(freq)

    # Попытка дешифровки путем сопоставления ключевых слов
    best_shift = None
    max_matches = -1
    for shift in range(100):
        cipher = CaesarCipher(shift)
        decrypted_text = cipher.decrypt(ciphertext)
        matches = analyzer.matches_keywords(decrypted_text)
        if matches > max_matches:
            max_matches = matches
            best_shift = shift

    if best_shift is not None:
        print(f"Наиболее вероятный сдвиг для дешифровки: {best_shift}")
        print(f"Количество совпадений ключевых слов: {max_matches}")
    else:
        print("Не удалось определить сдвиг для дешифровки.")


def main():
    parser = argparse.ArgumentParser(
        description="Шифр Цезаря: шифрование, дешифровка и частотный анализ.")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Шифрование
    encrypt_parser = subparsers.add_parser('encrypt', help='Зашифровать файл')
    encrypt_parser.add_argument('input', help='Путь к входному файлу')
    encrypt_parser.add_argument('output', help='Путь к выходному файлу')
    encrypt_parser.add_argument('shift', type=int, help='Сдвиг')

    # Дешифровка
    decrypt_parser = subparsers.add_parser('decrypt', help='Дешифровать файл')
    decrypt_parser.add_argument('input', help='Путь к зашифрованному файлу')
    decrypt_parser.add_argument('output', help='Путь к выходному файлу')
    decrypt_parser.add_argument('shift', type=int, help='Сдвиг')

    # Поиск сдвига методом ключевых слов
    analyze_parser = subparsers.add_parser(
        'analyze', help='Провести частотный анализ зашифрованного файла')
    analyze_parser.add_argument('input', help='Путь к зашифрованному файлу')
    analyze_parser.add_argument(
        'keywords', help='Путь к файлу с ключевыми словами')

    # Поиск сдвига методом частотного анализа
    freq_parser = subparsers.add_parser(
        'freq', help='Поиск сдвига методом частотного анализа')
    freq_parser.add_argument('input', help='Путь к зашифрованному файлу')
    args = parser.parse_args()

    if args.command == 'encrypt':
        encrypt_file(args.input, args.output, args.shift)
    elif args.command == 'decrypt':
        decrypt_file(args.input, args.output, args.shift)
    elif args.command == 'analyze':
        frequency_analysis(args.input, args.keywords)
    elif args.command == 'freq':
        frequency_detect_shift(args.input)


if __name__ == "__main__":
    main()
