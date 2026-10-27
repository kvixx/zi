//! Лабораторная работа №5. Работа алгоритма DES в режиме CBC
//! (Cipher Block Chaining).
//!
//! Шифрование:  Ci = DES(Mi ⊕ Ci−1, K),  C0 = IV;
//! Дешифрование: Mi = DES⁻¹(Ci, K) ⊕ Ci−1.
//!
//! 64-битовый начальный вектор C0 генерируется датчиком ПСЧ лабораторной
//! работы №3: T(i+1) = (5·T(i) + 51) mod 256, T(0) = 13 (8 байт).

mod des;

use std::io::{BufRead, Write};

use des::{decrypt_block, encrypt_block};

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

/// Добавление PKCS#7-дополнения до длины, кратной 8 байтам.
fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let pad = 8 - data.len() % 8;
    let mut out = data.to_vec();
    out.extend(std::iter::repeat(pad as u8).take(pad));
    out
}

/// CBC-шифрование целого сообщения (с PKCS#7-дополнением).
fn cbc_encrypt(data: &[u8], key: u64, iv: u64) -> Vec<u8> {
    let padded = pkcs7_pad(data);
    let mut prev = iv;
    let mut out = Vec::with_capacity(padded.len());
    for chunk in padded.chunks(8) {
        let mut block = [0u8; 8];
        block.copy_from_slice(chunk);
        prev = encrypt_block(des::bytes_to_block(&block) ^ prev, key);
        out.extend_from_slice(&des::block_to_bytes(prev));
    }
    out
}

/// CBC-дешифрование и снятие дополнения PKCS#7.
fn cbc_decrypt(cipher: &[u8], key: u64, iv: u64) -> Vec<u8> {
    let mut prev = iv;
    let mut out = Vec::with_capacity(cipher.len());
    for chunk in cipher.chunks(8) {
        let mut block = [0u8; 8];
        block.copy_from_slice(chunk);
        let m = decrypt_block(des::bytes_to_block(&block), key) ^ prev;
        prev = des::bytes_to_block(&block);
        out.extend_from_slice(&des::block_to_bytes(m));
    }
    // снятие PKCS#7-дополнения
    if let Some(&last) = out.last() {
        let pad = last as usize;
        if (1..=8).contains(&pad) {
            out.truncate(out.len() - pad);
        }
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
    let cipher = cbc_encrypt(data, KEY, iv);
    let dec = cbc_decrypt(&cipher, KEY, iv);

    println!("Ключ (hex): {:016X}", KEY);
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

    // Демонстрация особенностей CBC.
    let bit = 17;
    let mut corrupt = cipher.clone();
    let byte_idx = bit / 8;
    if byte_idx < corrupt.len() {
        corrupt[byte_idx] ^= 1 << (7 - bit % 8);
        let bad = cbc_decrypt(&corrupt, KEY, iv);
        let diff = (0..data.len()).filter(|&i| data.get(i) != bad.get(i)).count();
        println!("Искажение 1 бита (№{}) шифрограммы: {:?}", bit,
            String::from_utf8_lossy(&bad));
        println!("  несовпадающих байт с исходным текстом: {}", diff);
        println!("  (в CBC искажение затрагивает текущий и следующий блоки)");
    }

    {
        let sample = b"ABCDEFGHABCDEFGH"; // два идентичных 64-битовых блока
        let c = cbc_encrypt(sample, KEY, iv);
        let same = c[0..8] == c[8..16];
        println!("Одинаковые блоки ОТ (ABCDEFGHABCDEFGH):");
        println!("  блок ШТ 1: {}; блок ШТ 2: {}", hex(&c[0..8]), hex(&c[8..16]));
        println!("  блоки ШТ совпадают -> {}", if same { "ДА" } else { "НЕТ (цепочка блоков)" });
    }
}