//! 临时排查用：用项目自身的 mTLS 配置复现 ZoomKey CRM / JIRA 请求。
//!
//! 用法：
//!   cargo run --example zoomkey_probe -- <ca.pem> <cert.pem> <key.pem> <url>

use sealbox_lib::zoomkey::tls;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!("usage: zoomkey_probe <ca.pem> <cert.pem> <key.pem> <url> [POST_BODY]");
        std::process::exit(2);
    }
    let ca = std::fs::read_to_string(&args[1]).expect("read ca");
    let cert = std::fs::read_to_string(&args[2]).expect("read cert");
    let key = std::fs::read_to_string(&args[3]).expect("read key");
    let url = args[4].clone();
    let body = args.get(5).cloned();

    let config = match tls::build_client_config(&ca, &cert, &key) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("tls config failed: {err}");
            std::process::exit(1);
        }
    };

    let agent = ureq::builder()
        .tls_config(config)
        .redirects(0)
        .timeout(Duration::from_secs(30))
        .timeout_connect(Duration::from_secs(10))
        .user_agent("Sealbox/0.1")
        .max_idle_connections(if std::env::var("PROBE_POOL").is_ok() { 100 } else { 0 })
        .build();

    // 与 App 相同的顺序：GET getchallenge → POST login，共用同一个 agent（连接池）。
    let flow = std::env::var("PROBE_FLOW").is_ok();
    let steps: Vec<(bool, String, Option<String>)> = if flow {
        let base = url.clone();
        vec![
            (
                false,
                format!("{base}?operation=getchallenge&username=probe"),
                None,
            ),
            (
                true,
                base,
                Some("operation=login&username=probe&accessKey=00000000000000000000000000000000".into()),
            ),
        ]
    } else {
        let repeat = std::env::var("PROBE_REPEAT")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1);
        (0..repeat)
            .map(|_| (body.is_some(), url.clone(), body.clone()))
            .collect()
    };

    for (index, (is_post, url, body)) in steps.iter().enumerate() {
        println!("--> [{}] {} {}", index + 1, if *is_post { "POST" } else { "GET" }, url);
        let request = if *is_post {
            agent.post(url)
        } else {
            agent.get(url)
        };
        let request = request.set("Accept", "application/json");
        let result = match body {
            Some(body) => request
                .set("Content-Type", "application/x-www-form-urlencoded")
                .send_string(body),
            None => request.call(),
        };

        match result {
            Ok(response) => {
                let status = response.status();
                let text = response.into_string().unwrap_or_default();
                println!("<-- [{}] HTTP {status}", index + 1);
                println!("{text}");
            }
            Err(ureq::Error::Status(status, response)) => {
                println!("<-- [{}] HTTP {status} (status error)", index + 1);
                println!("{}", response.into_string().unwrap_or_default());
            }
            Err(err) => {
                println!("<-- [{}] TRANSPORT ERROR: {err}", index + 1);
                let mut source = std::error::Error::source(&err);
                while let Some(inner) = source {
                    println!("    caused by: {inner}");
                    source = inner.source();
                }
                std::process::exit(1);
            }
        }
    }
}
