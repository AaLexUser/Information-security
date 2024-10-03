import string
from collections import Counter
from typing import Optional

class FrequencyAnalyzer:
    def __init__(self, keywords_file: Optional[str] = None):
        self.keywords = self._load_keywords(keywords_file)
        # Define English and Russian alphabets
        self.english_lower = string.ascii_lowercase
        self.russian_lower = 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя'
        self.alphabet = self.english_lower + self.russian_lower
        
        # Define expected frequency distributions for English and Russian
        self.english_freq = {
            'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253,
            'e': 12.702, 'f': 2.228, 'g': 2.015, 'h': 6.094,
            'i': 6.966, 'j': 0.153, 'k': 0.772, 'l': 4.025,
            'm': 2.406, 'n': 6.749, 'o': 7.507, 'p': 1.929,
            'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
            'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150,
            'y': 1.974, 'z': 0.074
        }

        self.russian_freq = {
            'а': 8.01, 'б': 1.59, 'в': 4.54, 'г': 1.70,
            'д': 2.98, 'е': 8.45, 'ё': 0.04, 'ж': 0.94,
            'з': 1.65, 'и': 7.35, 'й': 1.21, 'к': 3.49,
            'л': 4.40, 'м': 3.21, 'н': 6.70, 'о': 10.97,
            'п': 2.81, 'р': 4.73, 'с': 5.47, 'т': 6.26,
            'у': 2.62, 'ф': 0.26, 'х': 0.97, 'ц': 0.48,
            'ч': 1.44, 'ш': 0.73, 'щ': 0.36, 'ъ': 0.04,
            'ы': 1.90, 'ь': 1.74, 'э': 0.32, 'ю': 0.64,
            'я': 2.01
        }

    def _load_keywords(self, filepath: Optional[str] = None):
        if filepath is None:
            return []
        with open(filepath, 'r', encoding='utf-8') as file:
            return [line.strip().lower() for line in file]

    def analyze(self, text):
        text = text.lower()
        filtered_text = [char for char in text if char in self.alphabet]
        freq = Counter(filtered_text)
        return freq

    def matches_keywords(self, text):
        text = text.lower()
        matches = 0
        for keyword in self.keywords:
            if keyword in text:
                matches += 1
        return matches
    
    def detect_shift(self, text):
        freq = self.analyze(text)
        
        # Normalize frequencies
        total = sum(freq.values())
        freq_percent = {char: (count / total) * 100 for char, count in freq.items()}
        
        # Detect English shift
        english_shift_scores = []
        for shift in range(26):
            score = 0.0
            for char in self.english_lower:
                shifted_char = self.english_lower[(self.english_lower.index(char) - shift) % 26]
                score += abs(freq_percent.get(char, 0) - self.english_freq[shifted_char]) 
            english_shift_scores.append((shift, score))
        # Select shift with minimum score
        english_shift = min(english_shift_scores, key=lambda x: x[1])[0]
        
        # Detect Russian shift
        russian_shift_scores = []
        for shift in range(33):
            score = 0.0
            for char in self.russian_lower:
                shifted_char = self.russian_lower[(self.russian_lower.index(char) - shift) % 33]
                score += abs(freq_percent.get(char, 0) - self.russian_freq[shifted_char])
            russian_shift_scores.append((shift, score))
        # Select shift with minimum score
        russian_shift = min(russian_shift_scores, key=lambda x: x[1])[0]
        
        return english_shift, russian_shift
