use argparse::ArgumentParser;
use argparse::Store;
use argparse::StoreOption;
use argparse::StoreTrue;
use bytes::Bytes;
use futures::channel::oneshot;
use futures::join;
use futures::StreamExt;
use futures::SinkExt;
use mumble_protocol_2x::control::msgs;
use mumble_protocol_2x::control::ClientControlCodec;
use mumble_protocol_2x::control::ControlPacket;
use mumble_protocol_2x::crypt::ClientCryptState;
use mumble_protocol_2x::voice::VoicePacket;
use mumble_protocol_2x::voice::VoicePacketPayload;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::fs::File;
use std::io::prelude::*;
use std::time::{Duration, SystemTime};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio_native_tls::TlsConnector;
use tokio_util::codec::Decoder;
use tokio_util::udp::UdpFramed;

async fn connect(
	server_addr: SocketAddr,
	server_host: String,
	user_name: String,
	password: Option<String>,
	accept_invalid_cert: bool,
	crypt_state_sender: oneshot::Sender<ClientCryptState>,
) {
	// Wrap crypt_state_sender in Option, so we can call it only once
	let mut crypt_state_sender = Some(crypt_state_sender);

	// Connect to server via TCP
	let stream = TcpStream::connect(&server_addr).await.expect("Failed to connect to server:");
	println!("TCP connected..");

	// Wrap the connection in TLS
	let mut builder = native_tls::TlsConnector::builder();
	builder.danger_accept_invalid_certs(accept_invalid_cert);
	let connector: TlsConnector = builder
		.build()
		.expect("Failed to create TLS connector")
		.into();
	let tls_stream = connector
		.connect(&server_host, stream)
		.await
		.expect("Failed to connect TLS: {}");
	println!("TLS connected..");

	// Wrap the TLS stream with Mumble's client-side control-channel codec
	let (mut sink, mut stream) = ClientControlCodec::new().framed(tls_stream).split();

	// Handshake (omitting `Version` message for brevity)
	let mut msg = msgs::Authenticate::new();
	msg.set_username(user_name);
	if let Some(password) = password {
		msg.set_password(password);
	}
	msg.set_opus(true);
	sink.send(msg.into()).await.unwrap();

	println!("Logging in..");
	let mut crypt_state = None;
	
	// Handle incoming packets
	while let Some(packet) = stream.next().await {
		//Send periodic Ping packets. TODO: make it so we space out our pings.
		let ping_packet = msgs::Ping::new();
		sink.send(ping_packet.into()).await.unwrap();
		
		match packet.unwrap() {
			ControlPacket::TextMessage(mut msg) => {
				println!(
					"Got message from user with session ID {}: {}",
					msg.actor(),
					msg.message()
				);
				// Send reply back to server
				let mut response = msgs::TextMessage::new();
				response.mut_session().push(msg.actor());
				response.set_message(msg.take_message());
				sink.send(response.into()).await.unwrap();
			}
			ControlPacket::CryptSetup(msg) => {
				// Wait until we're fully connected before initiating UDP voice
				crypt_state = Some(ClientCryptState::new_from(
					msg.key()
						.try_into()
						.expect("Server sent private key with incorrect size"),
					msg.client_nonce()
						.try_into()
						.expect("Server sent client_nonce with incorrect size"),
					msg.server_nonce()
						.try_into()
						.expect("Server sent server_nonce with incorrect size"),
				));
				println!(
					"Setup cryptSetup.\nCNonce: {:?}\nSNonce: {:?}\nKey: {:?}", //TODO: Remove this debug statment when done.
					crypt_state.as_ref().unwrap().get_encrypt_nonce(),
					crypt_state.as_ref().unwrap().get_decrypt_nonce(),
					crypt_state.as_ref().unwrap().get_key()
				);
			}
			ControlPacket::ServerSync(_) => {
				println!("Logged in!");
				if let Some(sender) = crypt_state_sender.take() {
					let _ = sender.send(
						crypt_state
							.take()
							.expect("Server didn't send us any CryptSetup packet!"),
					);
				}
			}
			ControlPacket::Reject(msg) => {
				println!("Login rejected: {:?}", msg);
			}
			_ => {},
		}
	}
}

async fn handle_udp(
	server_addr: SocketAddr,
	socket_addr: SocketAddr,
	crypt_state: oneshot::Receiver<ClientCryptState>,
) {
	// Bind UDP socket
	let udp_socket = UdpSocket::bind(&socket_addr)
		.await
		.expect("Failed to bind UDP socket");
	udp_socket.connect(&server_addr)
		.await
		.expect("Server should be reachable!");
	println!("Socket address: {}", socket_addr.to_string());
	println!("Server address: {}", server_addr.to_string());

	// Wait for initial CryptState
	let crypt_state = match crypt_state.await {
		Ok(crypt_state) => crypt_state,
		// disconnected before we received the CryptSetup packet, oh well
		Err(_) => return,
	};
	println!("UDP ready!");
	
	// Wrap the raw UDP packets in Mumble's crypto and voice codec (CryptState does both)
	let (mut sink, mut source) = UdpFramed::new(udp_socket, crypt_state).split();

	// Note: A normal application would also send periodic Ping packets, and its own audio
	//       via UDP. We instead trick the server into accepting us by sending it one
	//       dummy voice packet.
	let byte_array = Bytes::from([0u8; 128].as_ref()); //Makes a 128 segment array of uint8 equal to 0.
	let dummy_packet = (
		VoicePacket::Audio {
			_dst: std::marker::PhantomData,
			target: 0,
			session_id: (),
			seq_num: 0,
			payload: VoicePacketPayload::Opus(byte_array, true),
			position_info: None,
		},
		server_addr,
	);
	sink.send(dummy_packet).await;

	// Handle incoming UDP packets
	while let Some(packet) = source.next().await {
		//First unwrap the packet from the decryption so we can decrypt it.
		let (packet, src_addr) = match packet {
			Ok(packet) => packet,
			Err(err) => {
				eprintln!("Got an invalid UDP packet: {}", err);
				// To be expected, considering this is the internet, just ignore it
				continue
			}
		};
		//Now match the packet type for their individual handling.
		match packet {
			VoicePacket::Ping { 
				timestamp,
				..
			} => {
				//Note: A normal application would handle these and only use UDP for voice once it has received one. As far as I can tell, we just need to toss back UDP pings.
				let reply = VoicePacket::Ping {
					timestamp: timestamp,
				};
				sink.send((reply, src_addr)).await.unwrap();
			}
			VoicePacket::Audio {
				seq_num,
				payload,
				position_info,
				..
			} => {
				// Got audio, naively echo it back
				let reply = VoicePacket::Audio {
					_dst: std::marker::PhantomData,
					target: 0,      // normal speech
					session_id: (), // unused for server-bound packets
					seq_num,
					payload: payload,
					position_info,
				};
				sink.send((reply, src_addr)).await.unwrap();
			}
		}
	}
}

#[tokio::main]
async fn main() {
	// Handle command line arguments
	let mut server_host = "".to_string();
	let mut local_host = "".to_string();
	let mut server_port = 64738u16;
	let mut user_name = "EchoBot".to_string();
	let mut password = None;
	let mut accept_invalid_cert = false;
	{
		let mut ap = ArgumentParser::new();
		ap.set_description("Run the echo client example");
		ap.refer(&mut server_host)
			.add_option(&["--remote"], Store, "Hostname of mumble server")
			.required();
		ap.refer(&mut local_host)
			.add_option(&["--local"], Store, "Hostname of to bind our local socket to")
			.required();
		ap.refer(&mut server_port)
			.add_option(&["--port"], Store, "Port of mumble server");
		ap.refer(&mut user_name)
			.add_option(&["--username"], Store, "User name used to connect");
		ap.refer(&mut password)
			.add_option(&["--password"], StoreOption, "Server password used to connect");
		ap.refer(&mut accept_invalid_cert).add_option(
			&["--accept-invalid-cert"],
			StoreTrue,
			"Accept invalid TLS certificates",
		);
		ap.parse_args_or_exit();
	}
	let server_addr = (server_host.as_ref(), server_port)
		.to_socket_addrs()
		.expect("Failed to parse server address")
		.next()
		.expect("Failed to resolve server address");
	let local_socket_addr = (local_host.as_ref(), server_port)
		.to_socket_addrs()
		.expect("Failed to parse server address")
		.next()
		.expect("Failed to resolve server address");

	// Oneshot channel for setting UDP CryptState from control task
	// For simplicity we don't deal with re-syncing, real applications would have to.
	let (crypt_state_sender, crypt_state_receiver) = oneshot::channel::<ClientCryptState>();

	// Run it
	join!(
		connect(
			server_addr,
			server_host,
			user_name,
			password,
			accept_invalid_cert,
			crypt_state_sender,
		),
		handle_udp(
			server_addr,
			local_socket_addr,
			crypt_state_receiver,
		)
	);
}
