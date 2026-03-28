use std::time::Duration;

fn load_secret(env_var: &str) -> String {
    if let Ok(path) = std::env::var(env_var) {
        if let Ok(content) = std::fs::read_to_string(&path) {
            return content.trim().to_string();
        }
    }
    String::new()
}

fn main() {
    println!("=== Kloak Rust Demo (rustls - NOT interceptable) ===");

    let target_url = std::env::var("TARGET_URL")
        .unwrap_or_else(|_| "https://httpbin.org/headers".to_string());
    let interval: u64 = std::env::var("REQUEST_INTERVAL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);

    let secret_allowed = load_secret("SECRET_ALLOWED_FILE");
    let secret_blocked = load_secret("SECRET_BLOCKED_FILE");

    println!("Target URL: {}", target_url);
    println!("Request interval: {}s", interval);
    println!("Secret allowed loaded: {} bytes", secret_allowed.len());
    println!("Secret blocked loaded: {} bytes", secret_blocked.len());

    println!("Waiting 15 seconds for kloak to attach...");
    std::thread::sleep(Duration::from_secs(15));

    let client = reqwest::blocking::Client::new();

    loop {
        println!("\n--- Sending request ---");

        let result = client
            .get(&target_url)
            .header("X-Secret-Allowed", &secret_allowed)
            .header("X-Secret-Blocked", &secret_blocked)
            .header("Authorization", format!("Bearer {}", &secret_allowed))
            .send();

        match result {
            Ok(resp) => {
                println!("Status: {}", resp.status());
                println!("Response headers:");
                for (key, value) in resp.headers() {
                    println!("  {}: {}", key, value.to_str().unwrap_or("<binary>"));
                }
                match resp.text() {
                    Ok(body) => println!("Body:\n{}", body),
                    Err(e) => println!("Failed to read body: {}", e),
                }
            }
            Err(e) => {
                println!("Request failed: {}", e);
            }
        }

        std::thread::sleep(Duration::from_secs(interval));
    }
}
