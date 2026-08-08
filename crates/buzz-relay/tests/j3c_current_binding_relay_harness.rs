//! Public-interface loopback harness for current-binding presentation.
//!
//! This test intentionally imports the shared buzz-core protocol/fold surface.
//! It does not path-import or duplicate desktop implementation.

use std::time::Duration;

use buzz_core::client_binding_bootstrap::{
    ClientBindingBootstrapInputV1, ClientBindingEpoch, ClientBindingScopeV1,
    CLIENT_BINDING_BOOTSTRAP_SUB_ID, CLIENT_BINDING_SCOPE_TAG, CLIENT_BINDING_STATUS_SUB_ID,
};
use buzz_core::client_binding_status::{
    ClientBindingStatusDisposition, ClientBindingStatusInputV1,
};
use buzz_core::client_binding_status_session::{ClientBindingStatusSession, ProjectionUpdate};
use buzz_core::CommunityId;
use buzz_relay::protocol::RelayMessage;
use futures_util::{SinkExt, StreamExt};
use nostr::{Event, EventBuilder, Keys, Kind, Tag};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

const NOW: u64 = 1_800_000_000;
const FRESH_UNTIL: u64 = NOW + 120;

fn domain() -> CommunityId {
    CommunityId::from_uuid(Uuid::from_u128(0x1234))
}

fn epoch() -> ClientBindingEpoch {
    ClientBindingEpoch::parse("11111111-1111-4111-8111-111111111111")
        .expect("fixed harness epoch is canonical UUIDv4")
}

fn status(
    relay: &Keys,
    author: &Keys,
    revision: u64,
    disposition: ClientBindingStatusDisposition,
) -> Event {
    let input = match disposition {
        ClientBindingStatusDisposition::DisplayCurrent => ClientBindingStatusInputV1::current(
            domain(),
            author.public_key(),
            7,
            "19",
            revision,
            NOW,
            FRESH_UNTIL,
        ),
        ClientBindingStatusDisposition::Withdrawn => ClientBindingStatusInputV1::withdrawn(
            domain(),
            author.public_key(),
            revision,
            NOW,
            FRESH_UNTIL,
        ),
    }
    .expect("synthetic status input is valid");
    input
        .sign_with_relay_keys(relay)
        .expect("synthetic relay status signs")
}

async fn receive_text(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> String {
    let frame = timeout(Duration::from_secs(2), socket.next())
        .await
        .expect("loopback frame arrives before timeout")
        .expect("loopback relay remains connected")
        .expect("loopback frame is valid");
    match frame {
        Message::Text(text) => text.to_string(),
        other => panic!("expected text frame, got {other:?}"),
    }
}

#[tokio::test]
async fn j3c_loopback_consumes_public_bootstrap_and_status_fold() {
    let relay = Keys::generate();
    let author = Keys::generate();
    let bootstrap = ClientBindingBootstrapInputV1::new(domain(), author.public_key(), epoch(), NOW)
        .expect("synthetic bootstrap input is valid")
        .sign_with_relay_keys(&relay)
        .expect("synthetic relay bootstrap signs");
    assert_eq!(
        bootstrap.content,
        format!(
            "{{\"version\":1,\"authorization_domain\":\"{}\",\"event_author_pubkey\":\"{}\",\"connection_epoch\":\"{}\",\"issued_at\":{}}}",
            domain().as_uuid(),
            author.public_key().to_hex(),
            epoch().as_str(),
            NOW,
        ),
        "kind 24245 bootstrap bytes must remain unchanged",
    );

    let relay_hex = relay.public_key().to_hex();
    let auth = EventBuilder::new(Kind::Custom(22242), "")
        .tags([Tag::parse([
            CLIENT_BINDING_SCOPE_TAG,
            "1",
            epoch().as_str(),
            relay_hex.as_str(),
        ])
        .expect("synthetic AUTH scope tag is valid")])
        .sign_with_keys(&author)
        .expect("synthetic scoped AUTH signs");
    assert!(auth.verify().is_ok());
    let scope = ClientBindingScopeV1::from_verified_auth_event(&auth)
        .expect("verified AUTH exposes the public bootstrap scope");
    assert_eq!(scope.connection_epoch(), &epoch());
    assert_eq!(scope.relay_signer(), relay.public_key());

    let current = status(
        &relay,
        &author,
        1,
        ClientBindingStatusDisposition::DisplayCurrent,
    );
    assert!(
        !current.content.contains("connection_epoch"),
        "kind 24244 must remain epoch-free",
    );
    let newer = status(
        &relay,
        &author,
        2,
        ClientBindingStatusDisposition::DisplayCurrent,
    );
    let withdrawn = status(
        &relay,
        &author,
        3,
        ClientBindingStatusDisposition::Withdrawn,
    );
    let ordinary = json!(["NOTICE", "ordinary pass-through"]).to_string();
    let malformed_reserved = json!(["EVENT", CLIENT_BINDING_STATUS_SUB_ID]).to_string();
    let frames = vec![
        ordinary.clone(),
        RelayMessage::event(CLIENT_BINDING_BOOTSTRAP_SUB_ID, &bootstrap),
        RelayMessage::event(CLIENT_BINDING_STATUS_SUB_ID, &current),
        malformed_reserved,
        RelayMessage::event(CLIENT_BINDING_STATUS_SUB_ID, &current),
        RelayMessage::event(CLIENT_BINDING_STATUS_SUB_ID, &newer),
        RelayMessage::event(CLIENT_BINDING_STATUS_SUB_ID, &withdrawn),
    ];

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral loopback listener binds");
    let address = listener
        .local_addr()
        .expect("loopback listener has an address");
    assert!(address.ip().is_loopback());
    assert_ne!(address.port(), 0);
    let server = tokio::spawn(async move {
        let (tcp, peer) = listener.accept().await.expect("loopback client connects");
        assert!(peer.ip().is_loopback());
        let mut socket = tokio_tungstenite::accept_async(tcp)
            .await
            .expect("loopback WebSocket upgrades");
        for frame in frames {
            socket
                .send(Message::Text(frame.into()))
                .await
                .expect("loopback text frame sends");
        }
        socket.close(None).await.expect("loopback socket closes");
    });

    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{address}"))
        .await
        .expect("loopback client connects");
    let mut session =
        ClientBindingStatusSession::new(relay.public_key(), author.public_key(), epoch());

    let ordinary_received = receive_text(&mut socket).await;
    assert_eq!(ordinary_received, ordinary);
    assert!(session.consume_text(&ordinary_received, NOW).is_none());

    let bootstrap_received = receive_text(&mut socket).await;
    assert!(matches!(
        session.consume_text(&bootstrap_received, NOW),
        Some(ProjectionUpdate::Unchanged)
    ));
    let current_received = receive_text(&mut socket).await;
    let Some(ProjectionUpdate::Current(projection)) = session.consume_text(&current_received, NOW)
    else {
        panic!("fresh authenticated status must project current presentation");
    };
    assert_eq!(projection.event_author_pubkey, author.public_key().to_hex());
    assert_eq!(projection.fresh_until, FRESH_UNTIL);
    assert_eq!(projection.connection_epoch, epoch().as_str());

    let malformed_received = receive_text(&mut socket).await;
    assert!(matches!(
        session.consume_text(&malformed_received, NOW),
        Some(ProjectionUpdate::Clear)
    ));
    assert!(session.projected_fresh_until().is_none());

    let duplicate_received = receive_text(&mut socket).await;
    assert!(matches!(
        session.consume_text(&duplicate_received, NOW),
        Some(ProjectionUpdate::Unchanged)
    ));
    assert!(session.projected_fresh_until().is_none());

    let newer_received = receive_text(&mut socket).await;
    assert!(matches!(
        session.consume_text(&newer_received, NOW),
        Some(ProjectionUpdate::Current(_))
    ));
    assert!(matches!(
        session.expire(FRESH_UNTIL),
        ProjectionUpdate::Clear
    ));

    let withdrawn_received = receive_text(&mut socket).await;
    assert!(matches!(
        session.consume_text(&withdrawn_received, NOW),
        Some(ProjectionUpdate::Clear)
    ));

    server.await.expect("loopback server task completes");
}
