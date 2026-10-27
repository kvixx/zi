//! Лабораторная работа №4. Классический криптографический алгоритм DES
//! в режиме ECB (electronic code book).
//!
//! Программа шифрует произвольный открытый текст и дешифрует шифрограмму,
//! после результата компактно демонстрирует:
//!   * контрольный тест по вектору FIPS (85E813540F0AB405);
//!   * размножение ошибок режима ECB (искажение 1 бита шифрограммы);
//!   * недостаток ECB — одинаковые блоки ОТ дают одинаковые блоки ШТ;
//!   * работу на слабых ключах (DES(K, DES(K, ОТ)) = ОТ).

mod des;

use std::io::{BufRead, Write};

use des::{ecb_decrypt, ecb_encrypt};

const MAX: usize = 512;
const KEY: u64 = 0x1334_5779_9BBC_DFF1; // ключ по умолчанию (hex)

/// Слабые ключи DES
const WEAK_KEYS: [u64; 4] = [
    0x0101_0101_0101_0101,
    0xFEFE_FEFE_FEFE_FEFE,
    0x1F1F_1F1F_0E0E_0E0E,
    0xE0E0_E0E0_F1F1_F1F1,
];

fn hex(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>()
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

    // Основной результат: шифрование и дешифрование.
    let data = text.as_bytes();
    let cipher = ecb_encrypt(data, KEY);
    let dec = ecb_decrypt(&cipher, KEY);

    println!("Ключ (hex): {:016X}", KEY);
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

    // Демонстрация особенностей режима ECB.
    println!("Контрольный тест FIPS (ключ 133457799BBCDFF1, ОТ 0123456789ABCDEF,");
    println!(
        "  ожидается шифрограмма 85E813540F0AB405): {}",
        if des::self_test() {
            "ДА — реализация корректна"
        } else {
            "НЕТ"
        }
    );

    let bit = 17;
    let mut corrupt = cipher.clone();
    let byte_idx = bit / 8;
    if byte_idx < corrupt.len() {
        corrupt[byte_idx] ^= 1 << (7 - bit % 8);
        let bad = ecb_decrypt(&corrupt, KEY);
        let diff = (0..data.len())
            .filter(|&i| data.get(i) != bad.get(i))
            .count();
        println!(
            "Искажение 1 бита (№{}) шифрограммы: {:?} ({})",
            bit,
            String::from_utf8_lossy(&bad),
            if data.len() == bad.len() {
                format!("несовпадающих байт с ОТ: {}", diff)
            } else {
                format!("длина изменилась: {} != {}", bad.len(), data.len())
            }
        );
    }

    {
        let sample = b"ABCDEFGHABCDEFGH"; // два идентичных 64-битовых блока
        let c = ecb_encrypt(sample, KEY);
        let same = c[0..8] == c[8..16];
        println!(
            "Одинаковые блоки ОТ (ABCDEFGHABCDEFGH): блоки ШТ совпадают -> {}",
            if same {
                "ДА (недостаток ECB)"
            } else {
                "НЕТ"
            }
        );
    }

    {
        let plain: u64 = 0x0123_4567_89AB_CDEF;
        let ok = WEAK_KEYS
            .iter()
            .filter(|&&wk| {
                let c1 = des::encrypt_block(plain, wk);
                des::encrypt_block(c1, wk) == plain
            })
            .count();
        println!(
            "Слабые ключи DES(K, DES(K, ОТ)) = ОТ: {}/4 ключей совпадают",
            ok
        );
    }
}

