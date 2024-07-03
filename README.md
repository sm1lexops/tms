# Study questions Первостепенные IOC к сбору

Первостепенные индикаторы компрометации (Indicators of Compromise, IOC), которые необходимо собирать, зависят от типа угрозы и контекста, но можно выделить несколько категорий, которые являются критически важными для большинства сценариев:

## Сетевые индикаторы
- IP-адреса источников и целевых систем
- Доменные имена и URL-адреса, связанные с вредоносной активностью
- Хеши файлов (MD5, SHA-1, SHA-256) для обнаружения вредоносных программ
- Хосты, к которым осуществляется подозрительная активность
- Информация о SSL/TLS-сертификатах, используемых в подозрительных соединениях

## Файловые индикаторы
- Хеши файлов (MD5, SHA-1, SHA-256)
- Имена файлов и их атрибуты (размер, дата создания и модификации)
- Файловые пути и директории, где были обнаружены подозрительные файлы

## Системные индикаторы
- Запущенные процессы и их атрибуты (имена, PID, пути к исполняемым файлам)
- Подозрительные службы и драйверы, зарегистрированные в системе
- Изменения в реестре Windows (ключи и значения)

## Лог-файлы и события
- Записи в журналах безопасности и системе событий (например, попытки входа в систему, изменения в конфигурации)
- Логи межсетевых экранов, IDS/IPS и прокси-серверов
- Логи веб-серверов и баз данных

## Электронная почта и коммуникации
- Адреса электронной почты и заголовки писем, связанные с фишингом
- Прикрепленные файлы и ссылки в подозрительных сообщениях

## Индикаторы поведения
- Аномальное использование ресурсов (CPU, память, сеть)
- Необычные действия пользователя (например, входы в нерабочее время, доступ к необычным данным)

Сбор и анализ этих индикаторов помогают оперативно выявлять и реагировать на угрозы, минимизируя потенциальный ущерб.

примеры уязвимостей Python для отсутствия шифрования и использования слабых алгоритмов шифрования в формате Markdown:

## Примеры уязвимостей Python: Отсутствие шифрования и использование слабых алгоритмов шифрования

## Отсутствие шифрования

### Пример 1: Сохранение конфиденциальных данных в открытом виде

```python
def save_password(password):
    with open('passwords.txt', 'a') as f:
        f.write(password + '\n')

# Использование функции

save_password('my_secure_password')
```

Уязвимость

* Пароли сохраняются в текстовом файле в открытом виде, что делает их уязвимыми к краже.

Пример 2: Отправка данных по сети без шифрования

```python
import socket

def send_data(data, server_ip, server_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_ip, server_port))
        s.sendall(data.encode())
```

# Использование функции

> send_data('Sensitive information', '192.168.1.1', 8080)

Уязвимость

* Данные передаются по сети в открытом виде, что позволяет злоумышленникам перехватить и прочитать их.

Использование слабых алгоритмов шифрования

Пример 1: Использование устаревшего алгоритма DES

```python
from Crypto.Cipher import DES

def encrypt_data(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_data = data + (8 - len(data) % 8) * ' '
    encrypted_data = cipher.encrypt(padded_data.encode())
    return encrypted_data

# Использование функции

key = b'8bytekey'
encrypted = encrypt_data('Sensitive data', key)
print(encrypted)
```

Уязвимость

DES является устаревшим и слабым алгоритмом шифрования, который легко взломать с использованием современных технологий.

Пример 2: Использование слабых хеш-функций, таких как MD5

```python

import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Использование функции
hashed_password = hash_password('my_secure_password')
print(hashed_password)
```

Уязвимость

MD5 считается криптографически ненадежным, так как существуют известные методы для создания коллизий и взлома хешей.

### Рекомендации
* Используйте сильные алгоритмы шифрования: Рекомендуется использовать современные алгоритмы, такие как AES (Advanced Encryption Standard) для шифрования данных.

* Применяйте безопасные хеш-функции: Используйте алгоритмы хеширования, такие как SHA-256 или лучше, вместо устаревших MD5 и SHA-1.
* Шифруйте конфиденциальные данные: Всегда шифруйте конфиденциальные данные перед сохранением или передачей по сети.
* Используйте проверенные библиотеки: Используйте библиотеки, такие как cryptography для шифрования и хеширования данных.

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes

def encrypt_data(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(data.encode()) + encryptor.finalize()
    return encrypted_data

def hash_password(password):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password.encode())
    return digest.finalize()

# Использование функций
key = os.urandom(32)
encrypted = encrypt_data('Sensitive data', key)
hashed_password = hash_password('my_secure_password')
print(encrypted)
print(hashed_password)
```

## Input Validation

### Python Password Validation

# Python Regular Expression for Checking Password Requirements

This document provides an example of using Python's `re` module to check if a password meets certain requirements.

## Password Requirements

1. At least 8 characters long
2. Contains both uppercase and lowercase characters
3. Contains at least one numerical digit
4. Contains at least one special character (e.g., @, #, $, etc.)

## Python Script

```python
import re

def is_valid_password(password):
    """
    Validates the password based on the following criteria:
    1. At least 8 characters long
    2. Contains both uppercase and lowercase characters
    3. Contains at least one numerical digit
    4. Contains at least one special character
    """
    if len(password) < 8:
        return False

    if not re.search(r"[a-z]", password):
        return False

    if not re.search(r"[A-Z]", password):
        return False

    if not re.search(r"\d", password):
        return False

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False

    return True

# Example usage
passwords = ["Password123!", "password", "PASSWORD123", "Pass123", "Pass@123", "P@ssw0rd"]

for pwd in passwords:
    if is_valid_password(pwd):
        print(f"'{pwd}' is a valid password.")
    else:
        print(f"'{pwd}' is NOT a valid password.")
```

### Bash Script for Password Validation

```sh
#!/bin/bash

function is_valid_password() {
    local password=$1

    # Check if the password is at least 8 characters long
    if [[ ${#password} -lt 8 ]]; then
        echo "Password must be at least 8 characters long."
        return 1
    fi

    # Check if the password contains at least one lowercase letter
    if ! [[ $password =~ [a-z] ]]; then
        echo "Password must contain at least one lowercase letter."
        return 1
    fi

    # Check if the password contains at least one uppercase letter
    if ! [[ $password =~ [A-Z] ]]; then
        echo "Password must contain at least one uppercase letter."
        return 1
    fi

    # Check if the password contains at least one digit
    if ! [[ $password =~ [0-9] ]]; then
        echo "Password must contain at least one digit."
        return 1
    fi

    # Check if the password contains at least one special character
    if ! [[ $password =~ [\!\@\#\$\%\^\&\*\(\)\_\+\-\=\[\]\{\}\;\:\,\.\/\<\>\?\|] ]]; then
        echo "Password must contain at least one special character."
        return 1
    fi

    echo "Password is valid."
    return 0
}

# Example usage
passwords=("Password123!" "password" "PASSWORD123" "Pass123" "Pass@123" "P@ssw0rd")

for pwd in "${passwords[@]}"; do
    echo "Checking password: '$pwd'"
    is_valid_password "$pwd"
    echo
done
```

### Проверка формата телефонных номеров

```sh
#!/bin/bash

# Function to validate phone numbers
validate_phone_number() {
    local phone_number=$1
    local pattern1="^80(25|29|33|44)[0-9]{7}$"
    local pattern2="^375(25|29|33|44)[0-9]{7}$"

    if [[ $phone_number =~ $pattern1 ]]; then
        echo "$phone_number is valid (format: 80(25/29/33/44)xxxxxxx)"
    elif [[ $phone_number =~ $pattern2 ]]; then
        echo "$phone_number is valid (format: 375(25/29/33/44)xxxxxxx)"
    else
        echo "$phone_number is NOT valid"
    fi
}

# File containing phone numbers
file_path="phone_numbers.txt"  # Replace with your file path

# Read the file line by line and validate each phone number
while IFS= read -r line; do
    validate_phone_number "$line"
done < "$file_path"
```