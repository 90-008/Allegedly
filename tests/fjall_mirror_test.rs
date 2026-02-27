use allegedly::{
    ExperimentalConf, FjallDb, ListenConf, backfill_to_fjall, bin::bin_init, poll_upstream,
    serve_fjall,
};
use futures::TryFutureExt;
use reqwest::{StatusCode, Url};
use std::time::Duration;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_fjall_mirror_mode() -> anyhow::Result<()> {
    bin_init(false);
    let temp_dir = tempfile::tempdir()?;
    let db_path = temp_dir.path().join("fjall.db");
    let db = FjallDb::open(&db_path)?;

    // backfill (limited to 1 page)
    let (backfill_tx, backfill_rx) = mpsc::channel(1);
    let (upstream_tx, mut upstream_rx) = mpsc::channel(1);

    let upstream_url: Url = "https://plc.directory".parse()?;

    // spawn upstream poller
    tokio::spawn({
        let mut base = upstream_url.clone();
        base.set_path("/export");
        async move {
            // poll fresh data so our data matches the upstream
            let start_at = chrono::Utc::now() - chrono::Duration::try_minutes(5).unwrap();
            let _ = poll_upstream(
                Some(start_at),
                base,
                Duration::from_millis(100),
                upstream_tx,
            )
            .inspect_err(|err| log::error!("failed to poll upstream: {err}"))
            .await;
        }
    });

    log::info!("waiting for page from upstream...");
    let page = upstream_rx
        .recv()
        .await
        .expect("to receive page from upstream");
    log::info!("received page with {} ops", page.ops.len());
    let sample_did = page.ops.last().unwrap().did.clone();
    println!("will check did {sample_did}");

    backfill_tx.send(page).await?;
    let backfill_handle = tokio::spawn(backfill_to_fjall(db.clone(), false, backfill_rx, None));
    // since we are using a channel with 1 capacity, we can wait that the backfill task received
    // the page by reserving on the channel, and then drop the sender to signal the backfill task to finish
    let _ = backfill_tx.reserve().await;
    drop(backfill_tx);
    backfill_handle.await??;

    // todo: should probably use a random port here but shrug
    let listener = std::net::TcpListener::bind("127.0.0.1:17548")?;
    let port = listener.local_addr()?.port();
    drop(listener);

    let listen_conf = ListenConf::Bind(([127, 0, 0, 1], port).into());
    let exp_conf = ExperimentalConf {
        acme_domain: None,
        write_upstream: false,
    };

    let server_handle = tokio::spawn({
        let db = db.clone();
        let upstream = upstream_url.clone();
        serve_fjall(upstream, listen_conf, exp_conf, db)
            .inspect_err(|err| log::error!("failed to serve: {err}"))
    });
    let base_url = format!("http://127.0.0.1:{}", port);

    // wait for server to be ready
    let client = reqwest::Client::new();
    let health_url = format!("{base_url}/_health");
    let mut ready = None;
    for _ in 0..50 {
        let resp = match client.get(&health_url).send().await {
            Ok(resp) => resp,
            Err(err) => {
                log::warn!("failed to get health: {err}");
                continue;
            }
        };
        if resp.status().is_success() {
            let json: serde_json::Value = resp.json().await?;
            ready = Some(json);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready.is_some(), "server failed to start");
    assert_eq!(ready.unwrap()["server"], "allegedly (mirror/fjall)");

    // verify did resolution against upstream
    let mut doc_url = upstream_url.clone();
    doc_url.set_path(&format!("/{sample_did}"));
    let upstream_resp = client.get(doc_url).send().await?;
    assert_eq!(upstream_resp.status(), StatusCode::OK);
    let upstream_doc: serde_json::Value = upstream_resp.json().await?;

    let local_doc_url = format!("{base_url}/{sample_did}");
    let resp = client.get(local_doc_url).send().await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let doc: serde_json::Value = resp.json().await?;

    assert_eq!(
        doc, upstream_doc,
        "local doc != upstream doc.\nlocal: {:#?}\nupstream: {:#?}",
        doc, upstream_doc
    );

    server_handle.abort();
    Ok(())
}
