//! Лабораторная работа №2. Шифрование данных методом перестановки.
//!
//! Вариант 1: алфавит V = {а,б,…,я, a,b,…,z}, длина блока m = 15.
//!
//! Функция перестановки CN задана таблицей (номера позиций 1..15):
//!   i        : 1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
//!   CN(i)    : 15  1 12  8  3 14  5 10  2 13  6  9 11  4  7
//! Это означает: на i-й позиции блока шифртекста стоит символ,
//! занимавший позицию CN(i) в блоке открытого текста.
//!
//! Схема работы:
//!   1. Открытый текст разбивается на 15-символьные блоки; последний
//!      блок дополняется символом «а» до полного размера.
//!   2. Перед данными добавляется служебный блок — десятичная запись
//!      длины исходного текста, дополненная нулями до 15 символов.
//!   3. Каждый блок подвергается перестановке CN.
//!   4. Дешифрование — обратная перестановка CN⁻¹ каждого блока,
//!      чтение длины из служебного блока и отбрасывание дополнения.

use std::io::{BufRead, Write};

const M: usize = 15; // длина блока
const MAX: usize = 512;

/// Функция перестановки CN: на i-ю позицию шифртекста ставится
/// символ с позиции CN[i] открытого текста (номера 1..15).
const CN: [usize; M] = [15, 1, 12, 8, 3, 14, 5, 10, 2, 13, 6, 9, 11, 4, 7];

/// Обратная перестановка CN⁻¹ (вычисляется один раз при запуске).
fn inverse_perm() -> [usize; M] {
    let mut inv = [0usize; M];
    for (pos, &src) in CN.iter().enumerate() {
        inv[src - 1] = pos + 1;
    }
    inv
}

/// Проверка, что символ принадлежит алфавиту V (строчные русские и
/// латинские буквы).
fn in_alphabet(c: char) -> bool {
    matches!(c, 'а'..='я' | 'a'..='z')
}

/// Шифрование блока: на i-ю позицию результата ставится символ с
/// позиции CN[i] исходного блока.
fn permute_block(block: &[char], perm: &[usize; M]) -> Vec<char> {
    let mut out = vec![' '; M];
    for i in 0..M {
        out[i] = block[perm[i] - 1];
    }
    out
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

    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();

    // Проверка допустимости символов алфавита V.
    let bad: Vec<char> = chars.iter().copied().filter(|&c| !in_alphabet(c)).collect();
    if !bad.is_empty() {
        println!(
            "Ошибка: текст содержит символы, не входящие в алфавит V: {:?}",
            bad
        );
        return;
    }

    let inv = inverse_perm();
    let pad = (M - n % M) % M;

    // Служебный блок: длина текста (15 цифр, с ведущими нулями).
    let mut blocks: Vec<Vec<char>> = vec![];
    blocks.push(format!("{:015}", n).chars().collect());

    let mut block = Vec::with_capacity(M);
    for &c in &chars {
        block.push(c);
        if block.len() == M {
            blocks.push(std::mem::take(&mut block));
        }
    }
    while block.len() < M {
        block.push('а'); // дополнение последнего блока символом «а»
    }
    blocks.push(block);

    // Шифрование: перестановка CN каждого блока.
    let cipher_blocks: Vec<Vec<char>> = blocks
        .iter()
        .map(|b| permute_block(b, &CN))
        .collect();
    let cipher_text: String = cipher_blocks.iter().flatten().collect();

    println!("Открытый текст: {}", text);
    println!("Длина текста: {} символов, дополнение {} симв. «а»", n, pad);
    println!("Шифрограмма: {}", cipher_text);
    println!("Блоки шифрограммы:");
    for (i, b) in cipher_blocks.iter().enumerate() {
        println!("  [{}] {}", i, b.iter().collect::<String>());
    }

    // Дешифрование: обратная перестановка CN⁻¹.
    let dec_blocks: Vec<Vec<char>> = cipher_blocks
        .iter()
        .map(|b| permute_block(b, &inv))
        .collect();

    // Чтение длины из служебного блока.
    let header_dec: String = dec_blocks[0].iter().collect();
    let recovered_n: usize = header_dec.trim_start_matches('0').parse().unwrap_or(0);

    let mut plain: String = String::new();
    for b in &dec_blocks[1..] {
        plain.extend(b.iter());
    }
    plain = plain.chars().take(recovered_n).collect();

    println!("Длина из служебного блока: {}", recovered_n);
    println!("Дешифрованный текст: {}", plain);

    if plain == text {
        println!("Проверка пройдена: расшифрованный текст совпадает с исходным.");
    } else {
        println!("Ошибка: расшифрованный текст не совпадает с исходным!");
    }
}