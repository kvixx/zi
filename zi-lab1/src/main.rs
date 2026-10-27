//! Лабораторная работа №1. Шифрование данных методом подстановки.
//!
//! Вариант 1: алфавит V = {0, 1}, длина блока m = 5, число блоков |V|^m = 32.
//!
//! Функция шифрования:   CV(x) = (5·x + 3) mod 32,   x ∈ [0; 31].
//! Так как НОД(5, 32) = 1, отображение взаимно однозначно.
//! Функция дешифрования: CV⁻¹(y) = 13·(y − 3) mod 32,  где 13 ≡ 5⁻¹ (mod 32).

use std::io::{BufRead, Write};

const M: usize = 5;        // длина блока
const BLOCKS: usize = 1 << M; // число различных блоков (32)
const MAX: usize = 512;    // максимальная длина текста

/// Функция шифрования: CV(x) = (5·x + 3) mod 32.
fn cv(x: u8) -> u8 {
    ((5 * (x as i32) + 3) % BLOCKS as i32) as u8
}

/// Функция дешифрования: CV⁻¹(y) = 13·(y − 3) mod 32.
fn cv_inv(y: u8) -> u8 {
    let v = (13 * (y as i32 - 3)) % BLOCKS as i32;
    ((v + BLOCKS as i32) % BLOCKS as i32) as u8
}

/// Текст (байты) -> битовая строка (по 8 бит на байт, старшие биты первого).
fn text_to_bits(text: &[u8]) -> String {
    let mut bits = String::with_capacity(text.len() * 8);
    for &b in text {
        for i in (0..8).rev() {
            bits.push(if b & (1 << i) == 0 { '0' } else { '1' });
        }
    }
    bits
}

/// Битовая строка -> байты (по 8 бит).
fn bits_to_text(bits: &str) -> Vec<u8> {
    bits.as_bytes()
        .chunks(8)
        .map(|chunk| {
            let mut b = 0u8;
            for &c in chunk {
                b = (b << 1) | (c - b'0');
            }
            b
        })
        .collect()
}

/// 5-битовое значение -> строка из 5 символов '0'/'1'.
fn format_block(v: u8) -> String {
    format!("{:0width$b}", v, width = M)
}

/// Шифрование: битовая строка -> шифрограмма (последовательность 5-битовых блоков).
fn encrypt_bits(bits: &str) -> String {
    // Дополнение нулями справа до длины, кратной M; число бит дополнения
    // записывается в служебный первый блок.
    let pad = (M - bits.len() % M) % M;
    let mut padded = bits.to_string();
    padded.push_str(&"0".repeat(pad));

    let mut out = format_block(cv(pad as u8));
    for ch in padded.as_bytes().chunks(M) {
        let mut v = 0u8;
        for &c in ch {
            v = (v << 1) | (c - b'0');
        }
        out.push_str(&format_block(cv(v)));
    }
    out
}

/// Дешифрование: шифрограмма -> битовая строка.
fn decrypt_bits(cipher: &str) -> String {
    let pad = cv_inv(cipher_bytes(cipher)[0]) as usize;
    let mut plain = String::new();
    for &y in &cipher_bytes(cipher)[1..] {
        plain.push_str(&format_block(cv_inv(y)));
    }
    plain.truncate(plain.len().saturating_sub(pad));
    plain
}

/// Шифрограмма -> значения 5-битовых блоков.
fn cipher_bytes(cipher: &str) -> Vec<u8> {
    cipher
        .as_bytes()
        .chunks(M)
        .map(|ch| {
            let mut v = 0u8;
            for &c in ch {
                v = (v << 1) | (c - b'0');
            }
            v
        })
        .collect()
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

    let data = text.as_bytes();
    let bits = text_to_bits(data);
    let cipher = encrypt_bits(&bits);
    let back = bits_to_text(&decrypt_bits(&cipher));

    println!("Открытый текст: {}", text);
    println!("Длина текста: {} байт, {} бит", data.len(), bits.len());
    println!("Шифрограмма (блоки по 5 бит):");
    println!("  {}", cipher);
    println!("Дешифрованный текст: {}", String::from_utf8_lossy(&back));

    if back == data {
        println!("Проверка пройдена: расшифрованный текст совпадает с исходным.");
    } else {
        println!("Ошибка: расшифрованный текст не совпадает с исходным!");
    }
}