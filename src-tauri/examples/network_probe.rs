// Public, credential-free connectivity probe. No account files or OAuth tokens are accessed.
use std::error::Error;
#[tokio::main]
async fn main() {
    for direct in [false, true] {
        let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(12));
        if direct {
            builder = builder.no_proxy();
        }
        let client = builder.build().unwrap();
        match client.get("https://register.windsurf.com/").send().await {
            Ok(response) => println!("direct={direct}: HTTP {}", response.status()),
            Err(e) => {
                let mut source = e.source();
                println!(
                    "direct={direct}: timeout={} connect={}",
                    e.is_timeout(),
                    e.is_connect()
                );
                while let Some(cause) = source {
                    println!("  {cause}");
                    source = cause.source();
                }
            }
        }
    }
    let client = devin_switcher_lib::modules::auth_transport::client().unwrap();
    match devin_switcher_lib::modules::auth_transport::send(client.get("https://register.windsurf.com/exa.seat_management_pb.SeatManagementService/RegisterUser").timeout(std::time::Duration::from_secs(12)),None).await {
        Ok(response) => println!("automatic fallback: HTTP {} (GET without any credential)",response.status()),
        Err(error) => println!("automatic fallback failed: {error}"),
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{port}")).unwrap())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    match devin_switcher_lib::modules::auth_transport::send(client.get("https://register.windsurf.com/exa.seat_management_pb.SeatManagementService/RegisterUser").timeout(std::time::Duration::from_secs(12)),None).await {
        Ok(response)=>println!("known-closed proxy -> verified direct TLS: HTTP {} (GET without any credential)",response.status()),
        Err(error)=>println!("known-closed proxy fallback failed: {error}"),
    }
}
