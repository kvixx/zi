//! Лабораторная работа №3. Линейное шифрование данных (гаммирование).
//!
//! Вариант 1: параметры датчика ПСЧ A = 5, C = 51, T(0) = 13, B = 256.
//! Алфавит — расширенная таблица ASCII (256 элементов, коды 0..255).
//!
//! Линейный конгруэнтный датчик ПСЧ:
//!     T(i+1) = (A·T(i) + C) mod B,  B = 256 = 2^8.
//! Период максимален: C = 51 — нечётное, A mod 4 = 5 mod 4 = 1 (Д. Кнут).
//!
//! Шифрование:   Ci = (Pi + Gi) mod 256,  где Gi = T(i) — гамма.
//! Дешифрование: Pi = (Ci − Gi) mod 256.

use std::io::{BufRead, Write};

const A: u32 = 5;
const C: u32 = 51;
const T0: u32 = 13;
const B: u32 = 256;
const MAX: usize = 512;

/// Датчик ПСЧ: гамма длины `n` (последовательность ASCII-кодов).
fn generate_gamma(n: usize) -> Vec<u8> {
    let mut gamma = Vec::with_capacity(n);
    let mut t = T0;
    for _ in 0..n {
        gamma.push(t as u8);
        t = (A * t + C) % B;
    }
    gamma
}

/// Шифрование гаммированием: Ci = (Pi + Gi) mod 256.
fn encrypt(plain: &[u8], gamma: &[u8]) -> Vec<u8> {
    plain
        .iter()
        .zip(gamma)
        .map(|(&p, &g)| ((p as u32 + g as u32) % B) as u8)
        .collect()
}

/// Дешифрование: Pi = (Ci − Gi) mod 256.
fn decrypt(cipher: &[u8], gamma: &[u8]) -> Vec<u8> {
    cipher
        .iter()
        .zip(gamma)
        .map(|(&c, &g)| ((B + c as u32 - g as u32) % B) as u8)
        .collect()
}

/// Печать последовательности ASCII-кодов (по 16 в строке).
fn print_codes(data: &[u8]) {
    for chunk in data.chunks(16) {
        let row: Vec<String> = chunk.iter().map(|b| format!("{:3}", b)).collect();
        println!("  {}", row.join(" "));
    }
    println!();
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

    println!("Параметры датчика ПСЧ: A={}, C={}, T(0)={}, B={}", A, C, T0, B);
    println!("Формула гаммы: T(i+1) = (A*T(i) + C) mod B");
    println!();

    let data = text.as_bytes();
    let gamma = generate_gamma(data.len());

    println!("Гамма (последовательность ASCII-кодов):");
    print_codes(&gamma);

    let cipher = encrypt(data, &gamma);
    println!("Шифрограмма (ASCII-коды):");
    print_codes(&cipher);

    println!("Шифрограмма (текст): {:?}", String::from_utf8_lossy(&cipher));
    let dec = decrypt(&cipher, &gamma);
    println!("Расшифрованный открытый текст: {:?}", String::from_utf8_lossy(&dec));

    if dec == data {
        println!("Проверка пройдена: расшифрованный текст совпадает с исходным.");
    } else {
        println!("Ошибка: расшифрованный текст не совпадает с исходным!");
    }
}