use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use snarkos_account::Account;
use snarkos_node_bft::events::{ChallengeRequest, ChallengeResponse, Event, EventCodec};
use snarkos_node_tcp::{Config, Connection, ConnectionSide, P2P, Tcp};
use snarkos_node_tcp::protocols::Handshake;
use snarkvm::prelude::{Address, error, Field, Network, Rng, TestnetV0};
use snarkvm::prelude::narwhal::Data;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use tokio_stream::StreamExt;
use snarkos_node_bft_events::{DisconnectReason, EventTrait};
use futures_util::sink::SinkExt;
use snarkvm::synthesizer::Restrictions;

#[derive(Clone)]
pub struct SimpleNode<N: Network> {
    pub tcp: Tcp,
    pub account: Account<N>,
    pub ip: SocketAddr,
    _p: PhantomData<N>,
}

impl<N: Network> P2P for SimpleNode<N> {
    fn tcp(&self) -> &Tcp {
        &self.tcp
    }
}

#[async_trait::async_trait]
impl<N: Network> Handshake for SimpleNode<N> {
    const TIMEOUT_MS: u64 = 3_000_00;
    async fn perform_handshake(&self, mut connection: Connection) -> Result<Connection, io::Error> {
        // Perform the handshake.
        let peer_addr = connection.addr();
        let peer_side = connection.side();
        let stream = self.borrow_stream(&mut connection);

        let mut peer_ip = if peer_side == ConnectionSide::Initiator {
            println!("Gateway received a connection request from '{peer_addr}'");
            None
        } else {
            println!("Gateway is connecting to {peer_addr}...");
            Some(peer_addr)
        };

        let restrictions = Restrictions::load().unwrap();
        let restrictions_id = restrictions.restrictions_id();
        self.handshake_inner_initiator(peer_addr, peer_ip, restrictions_id, stream).await?;

        Ok(connection)
    }
}

/// A macro unwrapping the expected handshake event or returning an error for unexpected events.
macro_rules! expect_event {
    ($event_ty:path, $framed:expr, $peer_addr:expr) => {
        match $framed.try_next().await? {
            // Received the expected event, proceed.
            Some($event_ty(data)) => {
                println!("Gateway received '{}' from '{}'", data.name(), $peer_addr);
                data
            }
            // Received a disconnect event, abort.
            Some(Event::Disconnect(reason)) => {
                return Err(error(format!("'{}' disconnected: {reason:?}", $peer_addr)));
            }
            // Received an unexpected event, abort.
            Some(ty) => {
                return Err(error(format!(
                    "'{}' did not follow the handshake protocol: received {:?} instead of {}",
                    $peer_addr,
                    ty.name(),
                    stringify!($event_ty),
                )))
            }
            // Received nothing.
            None => {
                return Err(error(format!(
                    "'{}' disconnected before sending {:?}",
                    $peer_addr,
                    stringify!($event_ty)
                )))
            }
        }
    };
}

impl<N: Network> SimpleNode<N> {
    async fn handshake_inner_initiator<'a>(
        &'a self,
        peer_addr: SocketAddr,
        peer_ip: Option<SocketAddr>,
        restrictions_id: Field<N>,
        stream: &'a mut TcpStream,
    ) -> io::Result<(SocketAddr, Framed<&mut TcpStream, EventCodec<N>>)> {
        // This value is immediately guaranteed to be present, so it can be unwrapped.
        let peer_ip = peer_ip.unwrap();

        // Construct the stream.
        let mut framed = Framed::new(stream, EventCodec::<N>::handshake());

        // Initialize an RNG.
        let rng = &mut rand::rngs::OsRng;

        /* Step 1: Send the challenge request. */

        // Sample a random nonce.
        let our_nonce = rng.gen();
        // Send a challenge request to the peer.
        let our_request = ChallengeRequest::new(self.local_ip().port(), self.account.address(), our_nonce);
        send_event(&mut framed, peer_addr, Event::ChallengeRequest(our_request)).await?;

        /* Step 2: Receive the peer's challenge response followed by the challenge request. */

        // Listen for the challenge response message.
        let peer_response = expect_event!(Event::ChallengeResponse, framed, peer_addr);
        // Listen for the challenge request message.
        let peer_request = expect_event!(Event::ChallengeRequest, framed, peer_addr);


        // Sign the counterparty nonce.
        let response_nonce: u64 = rng.gen();
        let data = [peer_request.nonce.to_le_bytes(), response_nonce.to_le_bytes()].concat();
        let Ok(our_signature) = self.account.sign_bytes(&data, rng) else {
            return Err(error(format!("Failed to sign the challenge request nonce from '{peer_addr}'")));
        };
        // Send the challenge response.

        tokio::time::sleep(Duration::from_millis(1500)).await;
        let our_response =
            ChallengeResponse { restrictions_id, signature: Data::Object(our_signature), nonce: response_nonce };
        send_event(&mut framed, peer_addr, Event::ChallengeResponse(our_response)).await?;

        Ok((peer_ip, framed))
    }

    fn local_ip(&self) -> SocketAddr {
        self.ip
    }



    async fn connect(&self, peer_ip: SocketAddr)  {
        if let Err(err) = self.tcp.connect(peer_ip).await {
            println!("Connect to {peer_ip}, error: {err}");
        }
    }
}


async fn send_event<N: Network>(
    framed: &mut Framed<&mut TcpStream, EventCodec<N>>,
    peer_addr: SocketAddr,
    event: Event<N>,
) -> io::Result<()> {
    println!("Gateway is sending '{}' to '{peer_addr}'", event.name());
    framed.send(event).await
}


#[tokio::main]
async fn main() {
    let validator_target = SocketAddr::from_str(&std::env::var("VALIDATOR_TARGET").unwrap_or("127.0.0.1:5003".to_string())).unwrap();
    let mut nodes = vec![];
    for i in 0..10 {
        let port = 6000 + i;
        let ip = SocketAddr::from_str(&format!("0.0.0.0:{port}")).unwrap();
        let tcp = Tcp::new(Config::new(ip, 60000));
        let account = Account::try_from("APrivateKey1zkp8CZNn3yeCseEtxuVPbDCwSyhGW6yZKUYKfgXmcpoGPWH").unwrap();
        let node = SimpleNode::<TestnetV0> {
            tcp,
            account,
            ip,
            _p: Default::default(),
        };
        node.enable_handshake().await;
        nodes.push(node);
    }

    for node in nodes.iter() {
        let node = node.clone();
        tokio::spawn(async move {
            node.connect(validator_target).await;
        });
    }
    tokio::time::sleep(Duration::from_secs(3600)).await;
}