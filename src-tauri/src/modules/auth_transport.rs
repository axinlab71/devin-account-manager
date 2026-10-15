//! Shared transport only: do not change OAuth parameters or credential payloads.
use reqwest::{header::USER_AGENT, Client, RequestBuilder, Response};
use std::fmt;
use std::time::Duration;

#[derive(Debug)]
pub struct TransportError {
    initial: reqwest::Error,
    direct: Option<reqwest::Error>,
}
fn category(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        return "连接或响应超时";
    }
    if error.is_connect() {
        use std::error::Error;
        let mut source = error.source();
        while let Some(cause) = source {
            let text = cause.to_string().to_ascii_lowercase();
            if ["tls", "ssl", "handshake", "certificate"]
                .iter()
                .any(|s| text.contains(s))
            {
                return "TLS 握手或证书验证失败";
            }
            source = cause.source();
        }
        return "无法建立连接（网络、DNS 或代理异常）";
    }
    "请求传输失败"
}
impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.direct {
            Some(direct) => write!(
                f,
                "系统/环境代理连接失败：{}；直连尝试也失败：{}。请检查代理和网络后重新授权。",
                category(&self.initial),
                category(direct)
            ),
            None => write!(
                f,
                "{}。请检查网络后重试；若已在浏览器完成授权，请重新发起授权。",
                category(&self.initial)
            ),
        }
    }
}
impl std::error::Error for TransportError {}

/// API requests must not follow redirects: once a server responds, an OTP must not be replayed.
pub fn client() -> Result<Client, String> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| "无法初始化认证网络连接".to_string())
}

/// Retry exactly once, and only if no connection to the service was established.
/// A response, HTTP rejection, or timeout after connecting must never replay a one-time token.
/// Preserve per-request headers/body/URL and the upstream client's implicit user agent.
/// The direct client retains normal TLS certificate and hostname verification.
pub async fn send(
    builder: RequestBuilder,
    default_agent: Option<&str>,
) -> Result<Response, TransportError> {
    let (client, request) = builder.build_split();
    let mut request = request.map_err(|initial| TransportError {
        initial,
        direct: None,
    })?;
    if !request.headers().contains_key(USER_AGENT) {
        if let Some(agent) = default_agent {
            if let Ok(value) = agent.parse() {
                request.headers_mut().insert(USER_AGENT, value);
            }
        }
    }
    let retry = request.try_clone();
    match client.execute(request).await {
        Ok(response) => Ok(response),
        Err(initial) => {
            if !initial.is_connect() {
                return Err(TransportError {
                    initial,
                    direct: None,
                });
            }
            let Some(retry) = retry else {
                return Err(TransportError {
                    initial,
                    direct: None,
                });
            };
            let direct = Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
                .build();
            let direct = match direct {
                Ok(client) => client,
                Err(direct) => {
                    return Err(TransportError {
                        initial,
                        direct: Some(direct),
                    })
                }
            };
            direct
                .execute(retry)
                .await
                .map_err(|direct| TransportError {
                    initial,
                    direct: Some(direct),
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tiny_http::{Response as LocalResponse, Server, StatusCode};
    fn closed_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }
    #[tokio::test]
    async fn failed_proxy_retries_direct_and_preserves_payload_and_agent() {
        for explicit_agent in [false, true] {
            let server = Server::http("127.0.0.1:0").unwrap();
            let url = format!("http://{}/exchange", server.server_addr());
            let worker = std::thread::spawn(move || {
                let mut req = server
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap()
                    .unwrap();
                assert_eq!(req.method().as_str(), "POST");
                assert_eq!(req.url(), "/exchange");
                let agent = req
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("User-Agent"))
                    .unwrap()
                    .value
                    .as_str();
                assert_eq!(
                    agent,
                    if explicit_agent {
                        "explicit-register-agent"
                    } else {
                        "upstream-implicit-agent"
                    }
                );
                let mut body = String::new();
                req.as_reader().read_to_string(&mut body).unwrap();
                assert_eq!(body, "synthetic-one-time-credential");
                req.respond(LocalResponse::from_string("ok")).unwrap();
                assert!(server
                    .recv_timeout(Duration::from_millis(150))
                    .unwrap()
                    .is_none());
            });
            let client = Client::builder()
                .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{}", closed_port())).unwrap())
                .user_agent("upstream-implicit-agent")
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap();
            let mut req = client.post(url).body("synthetic-one-time-credential");
            if explicit_agent {
                req = req.header(USER_AGENT, "explicit-register-agent");
            }
            assert_eq!(
                send(req, Some("upstream-implicit-agent"))
                    .await
                    .unwrap()
                    .status(),
                200
            );
            worker.join().unwrap();
        }
    }
    #[tokio::test]
    async fn http_rejection_does_not_replay_one_time_request() {
        let server = Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}/exchange", server.server_addr());
        let worker = std::thread::spawn(move || {
            let req = server
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap();
            req.respond(LocalResponse::empty(StatusCode(401))).unwrap();
            assert!(server
                .recv_timeout(Duration::from_millis(200))
                .unwrap()
                .is_none());
        });
        let client = Client::builder().no_proxy().build().unwrap();
        assert_eq!(
            send(client.post(url).body("synthetic"), None)
                .await
                .unwrap()
                .status(),
            401
        );
        worker.join().unwrap();
    }
    #[tokio::test]
    async fn timeout_after_connect_does_not_replay_one_time_request() {
        let server = Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}/exchange", server.server_addr());
        let worker = std::thread::spawn(move || {
            let req = server
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap();
            std::thread::sleep(Duration::from_millis(300));
            let _ = req.respond(LocalResponse::empty(StatusCode(200)));
            assert!(server
                .recv_timeout(Duration::from_millis(150))
                .unwrap()
                .is_none());
        });
        let client = Client::builder().no_proxy().build().unwrap();
        let err = send(
            client
                .post(url)
                .body("synthetic")
                .timeout(Duration::from_millis(100)),
            None,
        )
        .await
        .unwrap_err();
        assert!(err.initial.is_timeout());
        assert!(err.direct.is_none());
        assert!(!err.to_string().contains("synthetic"));
        assert!(!err.to_string().contains("http://"));
        worker.join().unwrap();
    }
    #[tokio::test]
    async fn api_redirect_does_not_forward_or_replay_credential() {
        let server = Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}/exchange", server.server_addr());
        let redirect_url = url.replace("/exchange", "/other");
        let worker = std::thread::spawn(move || {
            let req = server
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap();
            req.respond(
                LocalResponse::empty(StatusCode(307))
                    .with_header(tiny_http::Header::from_bytes("Location", redirect_url).unwrap()),
            )
            .unwrap();
            assert!(server
                .recv_timeout(Duration::from_millis(200))
                .unwrap()
                .is_none());
        });
        assert_eq!(
            send(client().unwrap().post(url).body("synthetic"), None)
                .await
                .unwrap()
                .status(),
            307
        );
        worker.join().unwrap();
    }
}
