//! Throwaway Phase 0 zero-service relay tracer bullet.
//!
//! Enabled only by `BUZZ_LOCAL_MODE=1`. This deliberately bypasses the production
//! AppState so the spike can measure the coupling before a durable storage seam exists.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use nostr::filter::MatchEventOptions;
use nostr::{Event, Filter, Kind};
use tokio::sync::{broadcast, RwLock};
use tracing::{info, warn};
use uuid::Uuid;

use buzz_relay::protocol::{ClientMessage, RelayMessage};

pub(crate) struct Config {
    bind_addr: SocketAddr,
    relay_url: String,
}

impl Config {
    pub(crate) fn from_env() -> anyhow::Result<Option<Self>> {
        let enabled = std::env::var("BUZZ_LOCAL_MODE")
            .ok()
            .is_some_and(|value| matches!(value.trim(), "1" | "true" | "on"));
        if !enabled {
            return Ok(None);
        }
        let bind_addr = std::env::var("BUZZ_BIND_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:4000".into())
            .parse()
            .context("invalid BUZZ_BIND_ADDR")?;
        let relay_url =
            std::env::var("BUZZ_RELAY_URL").unwrap_or_else(|_| format!("ws://{bind_addr}"));
        Ok(Some(Self {
            bind_addr,
            relay_url,
        }))
    }
}

#[derive(Clone)]
struct LocalState {
    events: Arc<RwLock<Vec<Event>>>,
    fanout: broadcast::Sender<Event>,
    relay_url: Arc<str>,
}

pub(crate) async fn run(config: Config) -> anyhow::Result<()> {
    let (fanout, _) = broadcast::channel(1024);
    let state = LocalState {
        events: Arc::new(RwLock::new(Vec::new())),
        fanout,
        relay_url: config.relay_url.into(),
    };
    let app = Router::new()
        .route("/", get(ws_upgrade))
        .route("/_liveness", get(|| async { "ok" }))
        .route("/_readiness", get(|| async { "ok" }))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    info!(bind_addr = %config.bind_addr, "BUZZ_LOCAL_MODE active: in-memory store and fan-out; external services bypassed");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn ws_upgrade(ws: WebSocketUpgrade, State(state): State<LocalState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| serve_socket(socket, state))
}

async fn serve_socket(socket: WebSocket, state: LocalState) {
    let challenge = Uuid::new_v4().to_string();
    let (mut tx, mut rx) = socket.split();
    if tx
        .send(Message::Text(
            RelayMessage::auth_challenge(&challenge).into(),
        ))
        .await
        .is_err()
    {
        return;
    }

    let mut authenticated = false;
    let mut live = state.fanout.subscribe();
    let mut subscriptions: Vec<(String, Vec<Filter>)> = Vec::new();
    loop {
        tokio::select! {
            frame = rx.next() => {
                let Some(Ok(Message::Text(raw))) = frame else { break };
                let message = match ClientMessage::parse(&raw) {
                    Ok(message) => message,
                    Err(error) => {
                        let _ = tx.send(Message::Text(RelayMessage::notice(&error.to_string()).into())).await;
                        continue;
                    }
                };
                match message {
                    ClientMessage::Auth(event) => {
                        let accepted = verify_auth(&event, &challenge, &state.relay_url);
                        authenticated = accepted;
                        let reason = if accepted { "" } else { "auth-required: verification failed" };
                        let _ = tx.send(Message::Text(RelayMessage::ok(&event.id.to_hex(), accepted, reason).into())).await;
                    }
                    ClientMessage::Event(event) if authenticated => {
                        let id = event.id.to_hex();
                        if event.verify().is_err() {
                            let _ = tx.send(Message::Text(RelayMessage::ok(&id, false, "invalid: bad signature").into())).await;
                            continue;
                        }
                        let inserted = {
                            let mut events = state.events.write().await;
                            if events.iter().any(|stored| stored.id == event.id) { false } else {
                                events.push(event.clone());
                                true
                            }
                        };
                        if inserted { let _ = state.fanout.send(event); }
                        let _ = tx.send(Message::Text(RelayMessage::ok(&id, true, if inserted { "" } else { "duplicate" }).into())).await;
                    }
                    ClientMessage::Req { sub_id, filters } if authenticated => {
                        let events = state.events.read().await.clone();
                        for event in events.iter().filter(|event| matches_any(&filters, event)) {
                            if tx.send(Message::Text(RelayMessage::event(&sub_id, event).into())).await.is_err() { return; }
                        }
                        if tx.send(Message::Text(RelayMessage::eose(&sub_id).into())).await.is_err() { return; }
                        subscriptions.retain(|(existing, _)| existing != &sub_id);
                        subscriptions.push((sub_id, filters));
                    }
                    ClientMessage::Count { sub_id, filters } if authenticated => {
                        let count = state.events.read().await.iter().filter(|event| matches_any(&filters, event)).count() as u64;
                        let _ = tx.send(Message::Text(RelayMessage::count(&sub_id, count).into())).await;
                    }
                    ClientMessage::Close(sub_id) => subscriptions.retain(|(existing, _)| existing != &sub_id),
                    _ => { let _ = tx.send(Message::Text(RelayMessage::notice("auth-required: authenticate first").into())).await; }
                }
            }
            event = live.recv(), if authenticated => match event {
                Ok(event) => {
                    for (sub_id, _) in subscriptions.iter().filter(|(_, filters)| matches_any(filters, &event)) {
                        if tx.send(Message::Text(RelayMessage::event(sub_id, &event).into())).await.is_err() { return; }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => warn!(skipped, "local fan-out receiver lagged"),
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    }
}

fn verify_auth(event: &Event, challenge: &str, relay_url: &str) -> bool {
    event.kind == Kind::Authentication
        && event.verify().is_ok()
        && event
            .tags
            .iter()
            .any(|tag| tag.as_slice() == ["challenge", challenge])
        && event
            .tags
            .iter()
            .any(|tag| tag.as_slice() == ["relay", relay_url])
}

fn matches_any(filters: &[Filter], event: &Event) -> bool {
    filters.is_empty()
        || filters
            .iter()
            .any(|filter| filter.match_event(event, MatchEventOptions::default()))
}
