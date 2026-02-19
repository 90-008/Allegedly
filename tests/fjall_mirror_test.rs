use allegedly::{
    ExperimentalConf, FjallDb, ListenConf, backfill_to_fjall, poll_upstream, serve_fjall,
};
use reqwest::Url;
use std::time::Duration;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_fjall_mirror_mode() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    // setup
    let temp_dir = tempfile::tempdir()?;
    let db_path = temp_dir.path().join("fjall.db");
    let db = FjallDb::open(&db_path)?;

    // backfill (limited to 1 page)
    let (backfill_tx, backfill_rx) = mpsc::channel(1);
    let (upstream_tx, mut upstream_rx) = mpsc::channel(1);

    // spawn upstream poller
    let upstream_url: Url = "https://plc.directory/export".parse()?;
    tokio::spawn(async move {
        // poll fresh data so our data matches the upstream
        let start_at = chrono::Utc::now() - chrono::Duration::try_minutes(5).unwrap();
        let _ = poll_upstream(
            Some(start_at),
            upstream_url,
            Duration::from_millis(100),
            upstream_tx,
        )
        .await;
    });

    // bridge: take 1 page from upstream and forward to backfill
    println!("waiting for page from upstream...");
    let page = upstream_rx
        .recv()
        .await
        .expect("to receive page from upstream");
    println!("received page with {} ops", page.ops.len());
    let sample_did = page.ops.last().unwrap().did.clone();

    backfill_tx.send(page).await?;
    drop(backfill_tx); // close backfill input

    backfill_to_fjall(db.clone(), false, backfill_rx, None).await?;

    // get free port
    let listener = std::net::TcpListener::bind("127.0.0.1:17548")?;
    let port = listener.local_addr()?.port();
    drop(listener);

    let listen_conf = ListenConf::Bind(([127, 0, 0, 1], port).into());
    let exp_conf = ExperimentalConf {
        acme_domain: None,
        write_upstream: false,
    };

    let db_for_server = db.clone();
    let server_handle = tokio::spawn(async move {
        let upstream: Url = "https://plc.directory".parse().unwrap();
        serve_fjall(upstream, listen_conf, exp_conf, db_for_server).await
    });

    // wait for server to be ready (retry loop)
    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}", port);
    let mut ready = false;
    for _ in 0..50 {
        if client
            .get(format!("{}/_health", base_url))
            .send()
            .await
            .is_ok()
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "server failed to start");

    // verify health
    let resp = client.get(format!("{}/_health", base_url)).send().await?;
    assert!(resp.status().is_success());
    let json: serde_json::Value = resp.json().await?;
    assert_eq!(json["server"], "allegedly (mirror/fjall)");

    // verify did resolution against upstream
    let upstream_resp = client
        .get(format!("https://plc.directory/{}", sample_did))
        .send()
        .await?;
    assert!(upstream_resp.status().is_success());
    let upstream_doc: serde_json::Value = upstream_resp.json().await?;

    let resp = client
        .get(format!("{}/{}", base_url, sample_did))
        .send()
        .await?;
    assert!(resp.status().is_success());
    let doc: serde_json::Value = resp.json().await?;
    assert_eq!(
        doc, upstream_doc,
        "local doc != upstream doc.\nlocal: {:#?}\nupstream: {:#?}",
        doc, upstream_doc
    );

    server_handle.abort();
    Ok(())
}
