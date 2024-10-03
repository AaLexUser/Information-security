import pytest
from src.frequency_analysis import FrequencyAnalyzer
from src.caesar_cipher import CaesarCipher
from collections import Counter

@pytest.fixture
def analyzer(tmp_path):
    keywords_file = tmp_path / "keywords.txt"
    keywords_file.write_text("тест\nпример\nпитон\n")
    return FrequencyAnalyzer(str(keywords_file))

def test_analyze_empty(analyzer):
    freq = analyzer.analyze('')
    assert freq == Counter()

def test_analyze_only_non_alphabet(analyzer):
    freq = analyzer.analyze('123!@# ABC abc АБВ абв')
    expected = Counter({'a': 2, 'b': 2, 'c': 2, 'а':2, 'б':2, 'в':2})
    assert freq == expected

def test_analyze_mixed_text(analyzer):
    text = 'Тестирование частотного анализа! Пример текста.'
    freq = analyzer.analyze(text)
    expected_letters = 'тестированиечастотногоанализапримертекста'
    expected = Counter(expected_letters)
    assert freq == expected

def test_matches_keywords(analyzer):
    text = 'это тестовый пример для питона'
    matches = analyzer.matches_keywords(text)
    assert matches == 3

def test_matches_keywords_partial(analyzer):
    text = 'это тестовый пример без ключевых слов'
    matches = analyzer.matches_keywords(text)
    assert matches == 2

def test_no_keyword_matches(analyzer):
    text = 'это просто случайный текст'
    matches = analyzer.matches_keywords(text)
    assert matches == 0

def test_full_frequency_analysis(analyzer, tmp_path):
    # Create a ciphertext by encrypting a known text
    cipher = CaesarCipher(3)
    plaintext = 'тест пример питон безопасность'
    ciphertext = cipher.encrypt(plaintext)
    
    input_file = tmp_path / "ciphertext.txt"
    input_file.write_text(ciphertext)
    
    # Perform frequency analysis
    freq = analyzer.analyze(ciphertext)
    
    # Check frequency counts
    assert isinstance(freq, Counter)
    total_letters = sum(freq.values())
    assert total_letters == len('тестпримерпитонбезопасность')

    # Check keyword matching
    matches = analyzer.matches_keywords(cipher.decrypt(ciphertext))
    assert matches == 3