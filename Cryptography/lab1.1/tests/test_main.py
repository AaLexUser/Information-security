import pytest
import subprocess
import sys
from pathlib import Path

@pytest.fixture
def setup_files(tmp_path):
    # Create sample plaintext file
    plaintext = "Hello Привет"
    plaintext_file = tmp_path / "plaintext.txt"
    plaintext_file.write_text(plaintext, encoding='utf-8')
    
    # Create keywords file
    keywords = "тест\nпример\nпитон\nшифр\nбезопасность\nанализ\nчастота\ndencrypt\nencrypt\nprogram\n"
    keywords_file = tmp_path / "keywords.txt"
    keywords_file.write_text(keywords, encoding='utf-8')
    
    return plaintext_file, keywords_file

def test_encrypt_decrypt(setup_files, tmp_path):
    plaintext_file, _ = setup_files
    encrypted_file = tmp_path / "encrypted.txt"
    decrypted_file = tmp_path / "decrypted.txt"
    
    # Encrypt the file with shift 3
    subprocess.run([
        sys.executable, 
        str(Path(__file__).parents[2] / "src" / "main.py"), 
        "encrypt", 
        str(plaintext_file), 
        str(encrypted_file), 
        "3"
    ], check=True)
    
    # Decrypt the file with shift 3
    subprocess.run([
        sys.executable, 
        str(Path(__file__).parents[2] / "src" / "main.py"), 
        "decrypt", 
        str(encrypted_file), 
        str(decrypted_file), 
        "3"
    ], check=True)
    
    # Read decrypted content
    decrypted_content = decrypted_file.read_text(encoding='utf-8')
    assert decrypted_content == "Hello Привет"

def test_frequency_analysis(setup_files, tmp_path, capsys):
    plaintext_file, keywords_file = setup_files
    encrypted_file = tmp_path / "encrypted.txt"
    
    # Encrypt the plaintext
    subprocess.run([
        sys.executable, 
        str(Path(__file__).parents[2] / "src" / "main.py"), 
        "encrypt", 
        str(plaintext_file), 
        str(encrypted_file), 
        "3"
    ], check=True)
    
    # Perform frequency analysis
    subprocess.run([
        sys.executable, 
        str(Path(__file__).parents[2] / "src" / "main.py"), 
        "analyze", 
        str(encrypted_file), 
        str(keywords_file)
    ], check=True)
    
    captured = capsys.readouterr()
    assert "Частотный анализ зашифрованного текста:" in captured.out
    assert "Наиболее вероятный сдвиг для дешифровки: 3" in captured.out
    assert "Количество совпадений ключевых слов: 3" in captured.out

def test_invalid_shift(setup_files, tmp_path, capsys):
    plaintext_file, _ = setup_files
    encrypted_file = tmp_path / "encrypted_invalid_shift.txt"
    decrypted_file = tmp_path / "decrypted_invalid_shift.txt"
    
    # Encrypt the file with an invalid shift (e.g., negative shift)
    subprocess.run([
        sys.executable, 
        str(Path(__file__).parents[2] / "src" / "main.py"), 
        "encrypt", 
        str(plaintext_file), 
        str(encrypted_file), 
        "-5"
    ], check=True)
    
    # Decrypt the file with the same negative shift
    subprocess.run([
        sys.executable, 
        str(Path(__file__).parents[2] / "src" / "main.py"), 
        "decrypt", 
        str(encrypted_file), 
        str(decrypted_file), 
        "-5"
    ], check=True)
    
    decrypted_content = decrypted_file.read_text(encoding='utf-8')
    assert decrypted_content == "Hello Привет"

def test_nonexistent_input_file(tmp_path, capsys):
    encrypted_file = tmp_path / "nonexistent_encrypted.txt"
    
    # Attempt to encrypt a nonexistent file
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.run([
            sys.executable, 
            str(Path(__file__).parents[2] / "src" / "main.py"), 
            "encrypt", 
            "nonexistent.txt", 
            str(encrypted_file), 
            "3"
        ], check=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    
    captured = capsys.readouterr()
    assert "No such file or directory" in captured.err

def test_empty_keywords_file(tmp_path, capsys):
    plaintext_file = tmp_path / "plaintext_empty_keywords.txt"
    plaintext_file.write_text("Hello Привет", encoding='utf-8')
    
    encrypted_file = tmp_path / "encrypted_empty_keywords.txt"
    keywords_file = tmp_path / "empty_keywords.txt"
    keywords_file.write_text("", encoding='utf-8')
    
    # Encrypt the file
    subprocess.run([
        sys.executable, 
        str(Path(__file__).parents[2] / "src" / "main.py"), 
        "encrypt", 
        str(plaintext_file), 
        str(encrypted_file), 
        "3"
    ], check=True)
    
    # Perform frequency analysis with empty keywords
    subprocess.run([
        sys.executable, 
        str(Path(__file__).parents[2] / "src" / "main.py"), 
        "analyze", 
        str(encrypted_file), 
        str(keywords_file)
    ], check=True)
    
    captured = capsys.readouterr()
    assert "Количество совпадений ключевых слов: 0" in captured.out