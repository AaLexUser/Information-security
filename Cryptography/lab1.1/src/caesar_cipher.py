import string

class CaesarCipher:
    def __init__(self, shift):
        self.shift = shift
        # Define English and Russian alphabets
        self.english_lower = string.ascii_lowercase
        self.english_upper = string.ascii_uppercase
        self.russian_lower = 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя'
        self.russian_upper = 'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ'

    def encrypt(self, text):
        return self._shift_text(text, self.shift)

    def decrypt(self, text):
        return self._shift_text(text, -self.shift)

    def _shift_text(self, text, shift):
        shifted_text = []
        for char in text:
            shifted_char = char
            if char in self.english_lower:
                idx = self.english_lower.find(char)
                shifted_idx = (idx + shift) % 26
                shifted_char = self.english_lower[shifted_idx]
            elif char in self.english_upper:
                idx = self.english_upper.find(char)
                shifted_idx = (idx + shift) % 26
                shifted_char = self.english_upper[shifted_idx]
            elif char in self.russian_lower:
                idx = self.russian_lower.find(char)
                shifted_idx = (idx + shift) % len(self.russian_lower)
                shifted_char = self.russian_lower[shifted_idx]
            elif char in self.russian_upper:
                idx = self.russian_upper.find(char)
                shifted_idx = (idx + shift) % len(self.russian_upper)
                shifted_char = self.russian_upper[shifted_idx]
            shifted_text.append(shifted_char)
        return ''.join(shifted_text)