//! Voice channel packets and codecs

use std::fmt::Debug;
use std::io;
use std::io::{Cursor, Read};
use std::marker::PhantomData;

use crate::crypt::DecryptError;

use byteorder::ReadBytesExt;
use bytes::Buf;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;

use super::varint::BufMutExt;
use super::varint::ReadExt;

/// A packet transmitted via Mumble's voice channel.
#[derive(Clone, Debug, PartialEq)]
pub enum VoicePacket<Dst: VoicePacketDst> {
    /// Ping packets contain opaque timestamp-like values which should simply be echoed back.
    Ping {
        /// Opaque timestamp-like value.
        /// Unless this is the echo, no assumptions about it should be made.
        timestamp: u64,
    },
    /// Packet containing audio data.
    Audio {
        /// Destination. Required due to encoding differences depending on packet flow direction.
        _dst: PhantomData<Dst>,
        /// The target.
        ///
        /// Only values 0-31 are valid (when serialized, this field is 5-bits long).
        target: u8,
        /// Session ID. Absent when packet is [Serverbound].
        session_id: Dst::SessionId,
        /// Sequence number of the first audio frame in this packet.
        ///
        /// Packets may contain multiple frames, so this may increase by more than one per packet.
        seq_num: u64,
        /// The actual audio data
        payload: VoicePacketPayload,
        /// Positional audio information.
        ///
        /// Usually `[f32; 3]` but may contain additional or different data if all clients
        /// receiving this packet can deal with such values (e.g. games with builtin Mumble
        /// client may use this field to transmit additional data to other game clients).
        position_info: Option<Bytes>,
    },
}

/// Audio data payload of [VoicePacket]s.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum VoicePacketPayload {
    /// CELT Alpha (0.7.0) encoded audio frames.
    CeltAlpha(Vec<Bytes>),
    /// CELT Beta (0.11.0) encoded audio frames.
    CeltBeta(Vec<Bytes>),
    /// Speex encoded audio frames.
    Speex(Vec<Bytes>),
    /// Opus encoded audio frame with end-of-transmission bit.
    Opus(Bytes, bool),
}

/// A `Codec` implementation that parses a stream of data chunks into [VoicePacket]s.
///
/// The encoding and decoding of voice packets depends on their destination.
/// See [ServerVoiceCodec] and [ClientVoiceCodec] for the two most reasonable configurations.
#[derive(Debug, Default)]
pub struct VoiceCodec<EncodeDst: VoicePacketDst, DecodeDst: VoicePacketDst> {
    _encode_dst: PhantomData<EncodeDst>,
    _decode_dst: PhantomData<DecodeDst>,
}
/// The [VoiceCodec] used on the server side.
pub type ServerVoiceCodec = VoiceCodec<Clientbound, Serverbound>;
/// The [VoiceCodec] used on the client side.
pub type ClientVoiceCodec = VoiceCodec<Serverbound, Clientbound>;

impl<EncodeDst: VoicePacketDst, DecodeDst: VoicePacketDst> VoiceCodec<EncodeDst, DecodeDst> {
    /// Creates a new control codec.
    pub fn new() -> Self {
        Default::default()
    }
}

/// Zero-sized struct indicating server-bound packet direction.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Serverbound;
/// Zero-sized struct indicating client-bound packet direction.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Clientbound;

mod private {
    pub trait Sealed {}
    impl Sealed for super::Serverbound {}
    impl Sealed for super::Clientbound {}
}

/// Sealed trait for indicating voice packet direction.
///
/// The only two implementations are [Serverbound] and [Clientbound].
pub trait VoicePacketDst: private::Sealed + Default + PartialEq {
    /// Type of [VoicePacket::Audio::session_id](enum.VoicePacket.html#variant.Audio.field.session_id).
    type SessionId: Debug + Clone + PartialEq;
    /// Reads session id of packets traveling in this direction.
    fn read_session_id<T: Read + Sized>(buf: &mut T) -> Result<Self::SessionId, io::Error>;
    /// Writes session id to packets traveling in this direction.
    fn write_session_id(buf: &mut BytesMut, session_id: Self::SessionId);
}

impl VoicePacketDst for Serverbound {
    type SessionId = ();

    fn read_session_id<T: Read + Sized>(_buf: &mut T) -> Result<Self::SessionId, io::Error> {
        Ok(())
    }

    fn write_session_id(_buf: &mut BytesMut, _session_id: Self::SessionId) {}
}

impl VoicePacketDst for Clientbound {
    type SessionId = u32;

    fn read_session_id<T: Read + Sized>(buf: &mut T) -> Result<Self::SessionId, io::Error> {
        Ok(buf.read_varint()? as u32)
    }

    fn write_session_id(buf: &mut BytesMut, session_id: Self::SessionId) {
        buf.put_varint(u64::from(session_id))
    }
}

impl<EncodeDst: VoicePacketDst, DecodeDst: VoicePacketDst> VoiceCodec<EncodeDst, DecodeDst> {
    // Note: other code assumes this returns Ok(Some(_)) or Err(_) but never Ok(None)
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<VoicePacket<DecodeDst>>, io::Error> {
        let mut buf = Cursor::new(&src);
        let header = buf.read_u8()?;
        let kind = header >> 5;
        let target = header & 0b11111;
        let result = if kind == 1 {
            let timestamp = buf.read_varint()?;
            src.advance(src.len());
            VoicePacket::Ping { timestamp }
        } else {
            let session_id = DecodeDst::read_session_id(&mut buf)?;
            let seq_num = buf.read_varint()?;
            let payload = match kind {
                0 | 2 | 3 => {
                    let mut frames = Vec::new();
                    let position = buf.position();
                    src.advance(position as usize);
                    loop {
                        if src.is_empty() {
                            return Err(io::ErrorKind::UnexpectedEof.into());
                        }
                        let header = src[0];
                        src.advance(1);

                        let len = (header & !0x80) as usize;
                        if src.len() < len {
                            return Err(io::ErrorKind::UnexpectedEof.into());
                        }
                        frames.push(src.split_to(len).freeze());
                        if header & 0x80 != 0x80 {
                            break;
                        }
                    }
                    match kind {
                        0 => VoicePacketPayload::CeltAlpha(frames),
                        2 => VoicePacketPayload::Speex(frames),
                        3 => VoicePacketPayload::CeltBeta(frames),
                        _ => panic!(),
                    }
                }
                4 => {
                    let header = buf.read_varint()?;
                    let position = buf.position();
                    src.advance(position as usize);
                    let termination_bit = header & 0x2000 == 0x2000;
                    let len = (header & !0x2000) as usize;
                    if src.len() < len {
                        return Err(io::ErrorKind::UnexpectedEof.into());
                    }
                    let frame = src.split_to(len).freeze();
                    VoicePacketPayload::Opus(frame, termination_bit)
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unknown voice packet type",
                    ));
                }
            };
            let position_info = if src.is_empty() {
                None
            } else {
                Some(src.split().freeze())
            };
            VoicePacket::Audio {
                _dst: PhantomData,
                target,
                session_id,
                seq_num,
                payload,
                position_info,
            }
        };
        Ok(Some(result))
    }
}

#[cfg(feature = "tokio-codec")]
impl<EncodeDst: VoicePacketDst, DecodeDst: VoicePacketDst> tokio_util::codec::Decoder
    for VoiceCodec<EncodeDst, DecodeDst>
{
    type Item = VoicePacket<DecodeDst>;
    type Error = io::Error; // never

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.decode(src)
    }
}

#[cfg(feature = "asynchronous-codec")]
impl<EncodeDst: VoicePacketDst, DecodeDst: VoicePacketDst> asynchronous_codec::Decoder
    for VoiceCodec<EncodeDst, DecodeDst>
{
    type Item = VoicePacket<DecodeDst>;
    type Error = io::Error; // never

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.decode(src)
    }
}

impl<EncodeDst: VoicePacketDst, DecodeDst: VoicePacketDst> VoiceCodec<EncodeDst, DecodeDst> {
    fn encode(
        &mut self,
        item: VoicePacket<EncodeDst>,
        dst: &mut BytesMut,
    ) -> Result<(), io::Error> {
        match item {
            VoicePacket::Ping { timestamp } => {
                dst.reserve(11);
                dst.put_u8(0x20);
                dst.put_varint(timestamp);
            }
            VoicePacket::Audio {
                _dst,
                target,
                session_id,
                seq_num,
                payload,
                position_info,
            } => {
                let kind = match payload {
                    VoicePacketPayload::CeltAlpha(_) => 0,
                    VoicePacketPayload::Speex(_) => 2,
                    VoicePacketPayload::CeltBeta(_) => 3,
                    VoicePacketPayload::Opus(_, _) => 4,
                };
                dst.reserve(1 /*header*/ + 10 /*session_id*/ + 10 /*seq_num*/);
                dst.put_u8(kind << 5 | target & 0b11111);
                EncodeDst::write_session_id(dst, session_id);
                dst.put_varint(seq_num);
                match payload {
                    VoicePacketPayload::CeltAlpha(frames)
                    | VoicePacketPayload::Speex(frames)
                    | VoicePacketPayload::CeltBeta(frames) => {
                        dst.reserve(frames.iter().map(|frame| 1 + frame.len()).sum());
                        let mut iter = frames.iter().peekable();
                        while let Some(frame) = iter.next() {
                            let continuation = iter.peek().map(|_| 0x80).unwrap_or(0);
                            dst.put_u8(continuation | (frame.len() as u8));
                            dst.put(frame.as_ref());
                        }
                    }
                    VoicePacketPayload::Opus(frame, termination_bit) => {
                        dst.reserve(10 + frame.len());
                        let term_bit = if termination_bit { 0x2000 } else { 0 };
                        dst.put_varint(term_bit | (frame.len() as u64));
                        dst.put(frame);
                    }
                };
                if let Some(bytes) = position_info {
                    dst.extend_from_slice(&bytes);
                }
            }
        }
        Ok(())
    }
}

#[cfg(feature = "tokio-codec")]
impl<EncodeDst: VoicePacketDst, DecodeDst: VoicePacketDst>
    tokio_util::codec::Encoder<VoicePacket<EncodeDst>> for VoiceCodec<EncodeDst, DecodeDst>
{
    type Error = io::Error; // never

    fn encode(
        &mut self,
        item: VoicePacket<EncodeDst>,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        self.encode(item, dst)
    }
}

#[cfg(feature = "asynchronous-codec")]
impl<EncodeDst: VoicePacketDst, DecodeDst: VoicePacketDst> asynchronous_codec::Encoder
    for VoiceCodec<EncodeDst, DecodeDst>
{
    type Item = VoicePacket<EncodeDst>;
    type Error = io::Error; // never

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.encode(item, dst)
    }
}

//Apparently I was missing docs for this. Frankly this is taken from https://github.com/AvarianKnight/rust-mumble/blob/oss/src/voice.rs since the original library I forked from had only MAC address errors when attempting to negotiate the crypt state.
pub fn decode_voice_packet<DecodeDst: VoicePacketDst>(buf_mut: &mut BytesMut) -> Result<VoicePacket<DecodeDst>, DecryptError> {
    let mut buf = std::io::Cursor::new(&buf_mut);
    let header = buf.read_u8()?;
    let kind = header >> 5;
    let target = header & 0b11111;
    let result = if kind == 1 {
        let timestamp = buf.read_varint()?;
        buf_mut.advance(buf_mut.len());
        VoicePacket::Ping { timestamp }
    } else {
        let session_id = DecodeDst::read_session_id(&mut buf)?;
        let seq_num = buf.read_varint()?;
        let payload = match kind {
            0 | 2 | 3 => {
                let mut frames = Vec::new();
                let position = buf.position();
                buf_mut.advance(position as usize);
                loop {
                    if buf_mut.is_empty() {
                        return Err(DecryptError::Eof);
                    }
                    let header = buf_mut[0];
                    buf_mut.advance(1);

                    let len = (header & !0x80) as usize;
                    if buf_mut.len() < len {
                        return Err(DecryptError::Eof);
                    }
                    frames.push(buf_mut.split_to(len).freeze());
                    if header & 0x80 != 0x80 {
                        break;
                    }
                }
                match kind {
                    0 => crate::voice::VoicePacketPayload::CeltAlpha(frames),
                    2 => crate::voice::VoicePacketPayload::Speex(frames),
                    3 => crate::voice::VoicePacketPayload::CeltBeta(frames),
                    _ => panic!(),
                }
            }
            4 => {
                let header = buf.read_varint()?;
                let position = buf.position();
                buf_mut.advance(position as usize);
                let termination_bit = header & 0x2000 == 0x2000;
                let len = (header & !0x2000) as usize;
                if buf_mut.len() < len {
                    return Err(DecryptError::Eof);
                }
                let frame = buf_mut.split_to(len).freeze();
                crate::voice::VoicePacketPayload::Opus(frame, termination_bit)
            }
            _ => {
                return Err(DecryptError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown voice packet type",
                )));
            }
        };
        let position_info = if buf_mut.is_empty() { None } else { Some(buf_mut.split().freeze()) };
        VoicePacket::Audio {
            _dst: PhantomData,
            target,
            session_id,
            seq_num,
            payload,
            position_info,
        }
    };
    Ok(result)
}

//Apparently I was missing docs for this. Frankly this is taken from https://github.com/AvarianKnight/rust-mumble/blob/oss/src/voice.rs since the original library I forked from had only MAC address errors when attempting to negotiate the crypt state.
pub fn encode_voice_packet<EncodeDst: VoicePacketDst>(item: &VoicePacket<EncodeDst>, dst: &mut BytesMut) {
    match item {
        VoicePacket::Ping { timestamp } => {
            dst.reserve(11);
            dst.put_u8(0x20);
            dst.put_varint(*timestamp);
        }
        VoicePacket::Audio {
            _dst,
            target,
            session_id,
            seq_num,
            payload,
            position_info,
        } => {
            let kind = match payload {
                VoicePacketPayload::CeltAlpha(_) => 0,
                VoicePacketPayload::Speex(_) => 2,
                VoicePacketPayload::CeltBeta(_) => 3,
                VoicePacketPayload::Opus(_, _) => 4,
            };
            dst.reserve(1 /*header*/ + 10 /*session_id*/ + 10 /*seq_num*/);
            dst.put_u8(kind << 5 | target & 0b11111);
            EncodeDst::write_session_id(dst, session_id.clone());
            dst.put_varint(*seq_num);
            match payload {
                VoicePacketPayload::CeltAlpha(frames) | VoicePacketPayload::Speex(frames) | VoicePacketPayload::CeltBeta(frames) => {
                    dst.reserve(frames.iter().map(|frame| 1 + frame.len()).sum());
                    let mut iter = frames.iter().peekable();
                    while let Some(frame) = iter.next() {
                        let continuation = iter.peek().map(|_| 0x80).unwrap_or(0);
                        dst.put_u8(continuation | (frame.len() as u8));
                        dst.put(frame.as_ref());
                    }
                }
                VoicePacketPayload::Opus(frame, termination_bit) => {
                    dst.reserve(10 + frame.len());
                    let term_bit = if *termination_bit { 0x2000 } else { 0 };
                    dst.put_varint(term_bit | (frame.len() as u64));
                    dst.put(frame.as_ref());
                }
            };
            if let Some(bytes) = position_info {
                dst.extend_from_slice(bytes);
            }
        }
    }
}