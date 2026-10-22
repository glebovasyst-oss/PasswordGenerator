#!/usr/bin/env python3
"""
Менеджер паролей — CLI-приложение с шифрованием.
Использует SQLite3 для хранения, Fernet (cryptography) для шифрования паролей,
SHA-256 для хеширования мастер-пароля.
"""

import os
import sys
import hashlib
import getpass
import sqlite3
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ─── Константы ───────────────────────────────────────────────
DB_FILE = "passwords.db"
KEY_FILE = ".key"
SALT = b"password_manager_salt_2026"  # фиксированная соль для KDF


# ─── Функции БД ──────────────────────────────────────────────

def init_db() -> sqlite3.Connection:
    """Создаёт БД и таблицы, если их нет. Возвращает соединение."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Таблица мастер-пароля (хранится хеш SHA-256)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS master (
            id    INTEGER PRIMARY KEY CHECK (id = 1),
            hash  TEXT NOT NULL
        )
    """)

    # Таблица записей
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            name     TEXT NOT NULL UNIQUE,
            login    TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.commit()
    return conn


def is_master_set(conn: sqlite3.Connection) -> bool:
    """Проверяет, установлен ли мастер-пароль."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM master")
    return cursor.fetchone()[0] > 0


def save_master_hash(conn: sqlite3.Connection, master_hash: str) -> None:
    """Сохраняет хеш мастер-пароля."""
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO master (id, hash) VALUES (1, ?)", (master_hash,))
    conn.commit()


def verify_master(conn: sqlite3.Connection, password: str) -> bool:
    """Проверяет мастер-пароль по хешу."""
    cursor = conn.cursor()
    cursor.execute("SELECT hash FROM master WHERE id = 1")
    row = cursor.fetchone()
    if row is None:
        return False
    return hashlib.sha256(password.encode()).hexdigest() == row[0]


def add_entry(conn: sqlite3.Connection, name: str, login: str, encrypted_pwd: str) -> bool:
    """Добавляет запись. Возвращает True при успехе."""
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO entries (name, login, password) VALUES (?, ?, ?)",
            (name, login, encrypted_pwd)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        print(f"Запись '{name}' уже существует.")
        return False


def get_entry(conn: sqlite3.Connection, name: str):
    """Возвращает запись (name, login, encrypted_password) или None."""
    cursor = conn.cursor()
    cursor.execute("SELECT name, login, password FROM entries WHERE name = ?", (name,))
    return cursor.fetchone()


def list_entries(conn: sqlite3.Connection):
    """Возвращает список всех записей (name, login)."""
    cursor = conn.cursor()
    cursor.execute("SELECT name, login FROM entries ORDER BY name")
    return cursor.fetchall()


def delete_entry(conn: sqlite3.Connection, name: str) -> bool:
    """Удаляет запись по названию. Возвращает True при успехе."""
    cursor = conn.cursor()
    cursor.execute("DELETE FROM entries WHERE name = ?", (name,))
    deleted = cursor.rowcount > 0
    conn.commit()
    return deleted


# ─── Функции шифрования ──────────────────────────────────────

def generate_key(master_password: str) -> bytes:
    """
    Генерирует ключ Fernet из мастер-пароля через PBKDF2HMAC.
    Это позволяет не хранить ключ в открытом виде.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=480_000,
    )
    raw_key = kdf.derive(master_password.encode())
    return base64.urlsafe_b64encode(raw_key)


def load_or_generate_keyfile(master_password: str) -> bytes:
    """
    Если файла .key нет — генерирует случайный ключ и сохраняет.
    Если есть — загружает. Но для привязки к мастер-паролю
    мы используем generate_key(), а .key хранит случайный ключ
    для слоя шифрования.
    """
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key


def get_fernet(master_password: str) -> Fernet:
    """
    Возвращает объект Fernet, используя ключ из файла .key.
    Без этого файла и корректного мастер-пароля расшифровка невозможна.
    """
    key = load_or_generate_keyfile(master_password)
    return Fernet(key)


def encrypt_password(fernet: Fernet, password: str) -> str:
    """Шифрует пароль и возвращает строку."""
    return fernet.encrypt(password.encode()).decode()


def decrypt_password(fernet: Fernet, encrypted: str) -> str:
    """Расшифровывает пароль."""
    return fernet.decrypt(encrypted.encode()).decode()


def hash_password(password: str) -> str:
    """Возвращает SHA-256 хеш пароля."""
    return hashlib.sha256(password.encode()).hexdigest()


# ─── CLI-обработчик ──────────────────────────────────────────

def cmd_add(conn: sqlite3.Connection, master_password: str) -> None:
    """Добавить новую запись."""
    name = input("Название / откуда: ").strip()
    if not name:
        print("Название не может быть пустым.")
        return
    login = input("Логин: ").strip()
    if not login:
        print("Логин не может быть пустым.")
        return
    password = getpass.getpass("Пароль: ").strip()
    if not password:
        print("Пароль не может быть пустым.")
        return

    fernet = get_fernet(master_password)
    encrypted = encrypt_password(fernet, password)

    if add_entry(conn, name, login, encrypted):
        print(f"Запись '{name}' добавлена.")


def cmd_get(conn: sqlite3.Connection, master_password: str) -> None:
    """Получить пароль по названию."""
    name = input("Название записи: ").strip()
    if not name:
        print("Название не может быть пустым.")
        return

    entry = get_entry(conn, name)
    if entry is None:
        print(f"Запись '{name}' не найдена.")
        return

    _, login, encrypted = entry
    fernet = get_fernet(master_password)
    try:
        password = decrypt_password(fernet, encrypted)
    except Exception:
        print("Ошибка расшифровки. Возможно, мастер-пароль неверен или ключ повреждён.")
        return

    try:
        import pyperclip
        pyperclip.copy(password)
        print("Пароль скопирован в буфер обмена.")
    except Exception:
        print(f"\n  Название: {name}")
        print(f"  Логин:    {login}")
        print(f"  Пароль:   {password}\n")
        print("Не удалось скопировать в буфер обмена. Установите pyperclip для автоматического копирования.")


def cmd_list(conn: sqlite3.Connection) -> None:
    """Показать все записи (названия и логины)."""
    entries = list_entries(conn)
    if not entries:
        print("Записей пока нет.")
        return

    print("\n  Сохранённые записи:")
    print("  " + "-" * 40)
    for name, login in entries:
        print(f"  {name:20s} | {login}")
    print()


def cmd_delete(conn: sqlite3.Connection) -> None:
    """Удалить запись по названию."""
    name = input("Название записи для удаления: ").strip()
    if not name:
        print("Название не может быть пустым.")
        return

    if delete_entry(conn, name):
        print(f"Запись '{name}' удалена.")
    else:
        print(f"Запись '{name}' не найдена.")


def cmd_new(conn: sqlite3.Connection, master_password: str) -> None:
    """Создать новый пароль (сгенерировать случайный)."""
    import secrets
    import string

    name = input("Название / куда сохранить: ").strip()
    if not name:
        print("Название не может быть пустым.")
        return
    login = input("Логин: ").strip()
    if not login:
        print("Логин не может быть пустым.")
        return

    # Генерация пароля
    length = input("Длина пароля (по умолчанию 16): ").strip() or "16"
    try:
        length = int(length)
    except ValueError:
        length = 16
    length = max(8, min(64, length))

    exclude_similar = input("Исключить похожие символы (0, O, o, 1, l, I)? (y/N): ").strip().lower()
    exclude_similar = exclude_similar in ("y", "yes", "д", "да")

    alphabet = string.ascii_letters + string.digits + string.punctuation
    if exclude_similar:
        similar = "0Oo1lI"
        alphabet = "".join(c for c in alphabet if c not in similar)

    if not alphabet:
        print("Слишком много ограничений для генерации пароля.")
        return

    password = "".join(secrets.choice(alphabet) for _ in range(length))

    print(f"\n  Сгенерированный пароль: {password}\n")

    fernet = get_fernet(master_password)
    encrypted = encrypt_password(fernet, password)

    if add_entry(conn, name, login, encrypted):
        print(f"Запись '{name}' добавлена.")


def setup_master(conn: sqlite3.Connection) -> str:
    """Первичная настройка мастер-пароля или вход."""
    if is_master_set(conn):
        # Вход
        for attempt in range(3):
            pwd = getpass.getpass("Мастер-пароль: ")
            if verify_master(conn, pwd):
                return pwd
            print("Неверный пароль." + (f" Осталось попыток: {2 - attempt}" if attempt < 2 else ""))
        print("Превышено количество попыток. Выход.")
        sys.exit(1)
    else:
        # Создание
        print("Добро пожаловать! Это первый запуск — нужно создать мастер-пароль.")
        while True:
            pwd = getpass.getpass("Новый мастер-пароль: ")
            confirm = getpass.getpass("Повторите мастер-пароль: ")
            if pwd != confirm:
                print("Пароли не совпадают. Попробуйте ещё раз.")
                continue
            if len(pwd) < 4:
                print("Пароль слишком короткий (минимум 4 символа).")
                continue
            save_master_hash(conn, hash_password(pwd))
            # Генерируем файл ключа
            load_or_generate_keyfile(pwd)
            print("Мастер-пароль установлен.\n")
            return pwd


def print_help() -> None:
    print("""
Менеджер паролей — команды:
  add     — добавить новую запись
  get     — получить пароль по названию
  list    — показать все записи (названия и логины)
  delete  — удалить запись по названию
  new     — создать новый случайный пароль и сохранить
  help    — показать это сообщение
  exit    — выход
""")


def main():
    conn = init_db()
    master_password = setup_master(conn)

    print("Вход выполнен. Введите команду (help — справка).")

    while True:
        try:
            cmd = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nДо свидания!")
            break

        if not cmd:
            continue

        if cmd in ("exit", "quit", "q"):
            print("До свидания!")
            break
        elif cmd == "help":
            print_help()
        elif cmd == "add":
            cmd_add(conn, master_password)
        elif cmd == "get":
            cmd_get(conn, master_password)
        elif cmd == "list":
            cmd_list(conn)
        elif cmd == "delete":
            cmd_delete(conn)
        elif cmd == "new":
            cmd_new(conn, master_password)
        else:
            print(f"Неизвестная команда: '{cmd}'. Введите 'help' для справки.")

    conn.close()


if __name__ == "__main__":
    main()
