use std::env;
use std::thread;
use std::time::Duration;

fn load_secret(env_var: &str) -> String {
    if let Ok(path) = env::var(env_var) {
        if let Ok(content) = std::fs::read_to_string(&path) {
            println!("Loaded secret from {}", path);
            return content.trim().to_string();
        }
    }
    String::new()
}

fn limit_len(s: &str, max: usize) -> &str {
    if s.len() > max {
        &s[..max]
    } else {
        s
    }
}

fn main() {
    let key_allowed = load_secret("SECRET_ALLOWED_FILE");
    let key_blocked = load_secret("SECRET_BLOCKED_FILE");

    let target_url = env::var("TARGET_URL")
        .unwrap_or_else(|_| "https://httpbin.org/headers".to_string());

    let interval: u64 = env::var("REQUEST_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    let sep = "=".repeat(60);
    println!("{}", sep);
    println!("Kloak Rust Demo: minreq + rustls (NOT interceptable)");
    println!("{}", sep);
    println!("Target URL: {}\n", target_url);
    println!("Secrets (as seen by the app - these are UUIDs if Kloak is working):");
    println!("  Secret Allowed (httpbin.org): {}...", limit_len(&key_allowed, 30));
    println!("  Secret Blocked (example.com): {}...\n", limit_len(&key_blocked, 30));
    println!("Expected behavior:");
    println!("  - X-Secret-Allowed: Should show ORIGINAL value in response");
    println!("  - X-Secret-Blocked: Should show UUID in response (not replaced)");
    println!("{}", sep);

    println!("Waiting 15s for Kloak controller to sync...");
    thread::sleep(Duration::from_secs(15));

    let mut request_count = 0u64;
    loop {
        request_count += 1;
        println!("\n--- Request #{} ---", request_count);

        let result = minreq::get(&target_url)
            .with_header("X-Secret-Allowed", &key_allowed)
            .with_header("X-Secret-Blocked", &key_blocked)
            .with_header("Authorization", &format!("Bearer {}", key_allowed))
            .send();

        match result {
            Ok(resp) => {
                println!("Status: {}", resp.status_code);
                println!("Response headers echoed back by httpbin:");
                match resp.as_str() {
                    Ok(body) => {
                        if body.len() > 800 {
                            println!("{}", &body[..800]);
                        } else {
                            println!("{}", body);
                        }
                    }
                    Err(e) => println!("Error reading body: {}", e),
                }
            }
            Err(e) => println!("Error: {}", e),
        }

        println!("\nWaiting {}s before next request...", interval);
        thread::sleep(Duration::from_secs(interval));
    }
}
