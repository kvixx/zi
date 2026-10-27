//! Лабораторная работа №6. Работа алгоритма DES в режиме CFB
//! (Cipher FeedBack, обратная связь по шифртексту), k = 8 бит.
//!
//! Регистр сдвига R (64 бита) инициализируется вектором C0 (датчик ПСЧ ЛР3).
//! Шифрование байта:  ci = mi ⊕ left8(DES(R, K));  R = (R << 8) | ci.
//! Дешифрование:      mi = ci ⊕ left8(DES(R, K));  R = (R << 8) | ci.
//! Сдвиг не является циклическим: левые 8 бит выталкиваются из регистра.

mod des;

use std::io::{BufRead, Write};

const MAX: usize = 512;
const KEY: u64 = 0x1334_5779_9BBC_DFF1; // ключ по умолчанию (hex)

/// Начальный вектор C0 = 8 байт датчика ПСЧ ЛР3 (A=5, C=51, T(0)=13, B=256).
fn gen_iv() -> u64 {
    let mut t: u32 = 13;
    let mut iv: u64 = 0;
    for _ in 0..8 {
        iv = (iv << 8) | t as u64;
        t = (5 * t + 51) % 256;
    }
    iv
}

/// CFB-шифрование (k = 8 бит). Возвращает байты шифртекста той же длины.
fn cfb_encrypt(data: &[u8], key: u64, iv: u64) -> Vec<u8> {
    let mut reg = iv;
    let mut out = Vec::with_capacity(data.len());
    for &m in data {
        let t = des::encrypt_block(reg, key);
        let gamma = (t >> 56) as u8; // 8 старших бит
        let c = m ^ gamma;
        reg = (reg << 8) | c as u64;
        out.push(c);
    }
    out
}

/// CFB-дешифрование (k = 8 бит). Регистр обновляется байтами шифртекста.
fn cfb_decrypt(cipher: &[u8], key: u64, iv: u64) -> Vec<u8> {
    let mut reg = iv;
    let mut out = Vec::with_capacity(cipher.len());
    for &c in cipher {
        let t = des::encrypt_block(reg, key);
        let gamma = (t >> 56) as u8;
        out.push(c ^ gamma);
        reg = (reg << 8) | c as u64;
    }
    out
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02X}", b)).collect::<String>()
}

/// Чтение одной строки со стандартного ввода.
fn read_line() -> String {
    print!("Введите открытый текст: ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return String::new();
    }
    line.trim_end_matches(['\r', '\n']).to_string()
}

fn main() {
    let text = read_line();
    if text.is_empty() {
        println!("Пустой ввод.");
        return;
    }
    if text.len() > MAX {
        println!("Текст слишком длинный (макс {} символов).", MAX);
        return;
    }

    let iv = gen_iv();
    let data = text.as_bytes();
    let cipher = cfb_encrypt(data, KEY, iv);
    let dec = cfb_decrypt(&cipher, KEY, iv);

    println!("Ключ (hex): {:016X}", KEY);
    println!("Размер k-битового блока: k = 8 бит (посимвольное шифрование)");
    println!("Начальный вектор C0 (hex): {:016X} (датчик ПСЧ ЛР3: A=5, C=51, T(0)=13, B=256)", iv);
    println!("Открытый текст: {}", text);
    println!("Шифрограмма ({} байт, hex):", cipher.len());
    println!("  {}", hex(&cipher));
    println!("Дешифрованный текст: {}", String::from_utf8_lossy(&dec));
    if dec == data {
        println!("Проверка пройдена: расшифрованный текст совпадает с исходным.");
    } else {
        println!("Ошибка: расшифрованный текст не совпадает с исходным!");
    }
    println!();

    // Демонстрация особенностей CFB.
    let bit = 17;
    let mut corrupt = cipher.clone();
    let byte_idx = bit / 8;
    if byte_idx < corrupt.len() {
        corrupt[byte_idx] ^= 1 << (7 - bit % 8);
        let bad = cfb_decrypt(&corrupt, KEY, iv);
        let diff = (0..data.len()).filter(|&i| data.get(i) != bad.get(i)).count();
        println!("Искажение 1 бита (№{}) шифрограммы: {:?}", bit,
            String::from_utf8_lossy(&bad));
        println!("  несовпадающих байт с исходным текстом: {}", diff);
        println!("  (в CFB искажается текущий байт и содержимое регистра —");
        println!("   ещё 8 байт следующего шифрования)");
    }

    {
        let sample = b"ABCDEFGHABCDEFGH"; // два идентичных 64-битовых блока
        let c = cfb_encrypt(sample, KEY, iv);
        let same = c[0..8] == c[8..16];
        println!("Одинаковые блоки ОТ (ABCDEFGHABCDEFGH):");
        println!("  блок ШТ 1: {}; блок ШТ 2: {}", hex(&c[0..8]), hex(&c[8..16]));
        println!("  блоки ШТ совпадают -> {}", if same { "ДА" } else { "НЕТ (позиция в потоке)" });
    }
}