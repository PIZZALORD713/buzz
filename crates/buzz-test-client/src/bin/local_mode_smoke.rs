//! Phase 0 local-mode smoke: two authenticated clients, live fan-out, history and COUNT.
use buzz_test_client::{BuzzTestClient, RelayMessage};
use nostr::{Filter, Keys};
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ws://127.0.0.1:4317".into());
    let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000001")?;
    if std::env::args().nth(2).as_deref() == Some("history-only") {
        let mut history = BuzzTestClient::connect(&url, &keys).await?;
        history
            .subscribe("restart-history", vec![Filter::new()])
            .await?;
        match history.recv_event(Duration::from_secs(2)).await? {
            RelayMessage::Event { event, .. } => {
                anyhow::ensure!(event.content == "phase0 live")
            }
            other => anyhow::bail!("expected persisted EVENT, got {other:?}"),
        }
        println!("PASS sqlite_restart_history");
        return Ok(());
    }
    let mut subscriber = BuzzTestClient::connect(&url, &keys).await?;
    subscriber.subscribe("live", vec![Filter::new()]).await?;
    let _ = subscriber.recv_event(Duration::from_secs(1)).await?; // EOSE
    let mut publisher = BuzzTestClient::connect(&url, &keys).await?;
    let ok = publisher
        .send_text_message(
            &keys,
            "00000000-0000-0000-0000-000000000042",
            "phase0 live",
            9,
        )
        .await?;
    anyhow::ensure!(ok.accepted, "publish rejected: {}", ok.message);
    match subscriber.recv_event(Duration::from_secs(2)).await? {
        RelayMessage::Event { event, .. } => anyhow::ensure!(event.content == "phase0 live"),
        other => anyhow::bail!("expected live EVENT, got {other:?}"),
    }
    let mut history = BuzzTestClient::connect(&url, &keys).await?;
    history.subscribe("history", vec![Filter::new()]).await?;
    match history.recv_event(Duration::from_secs(2)).await? {
        RelayMessage::Event { event, .. } => anyhow::ensure!(event.content == "phase0 live"),
        other => anyhow::bail!("expected historical EVENT, got {other:?}"),
    }
    println!("PASS nip42,event_insert,req_history,live_fanout");
    Ok(())
}
