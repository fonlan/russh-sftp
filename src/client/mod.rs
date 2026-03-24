pub mod error;
pub mod fs;
mod handler;
pub mod rawsession;
mod session;

pub use handler::Handler;
pub use rawsession::RawSftpSession;
pub use session::SftpSession;

use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};

use crate::{error::Error, protocol::Packet, utils::read_packet};

fn packet_summary(packet: &Packet) -> (&'static str, Option<u32>) {
    match packet {
        Packet::Version(_) => ("VERSION", None),
        Packet::Status(p) => ("STATUS", Some(p.id)),
        Packet::Handle(p) => ("HANDLE", Some(p.id)),
        Packet::Data(p) => ("DATA", Some(p.id)),
        Packet::Name(p) => ("NAME", Some(p.id)),
        Packet::Attrs(p) => ("ATTRS", Some(p.id)),
        Packet::ExtendedReply(p) => ("EXTENDED_REPLY", Some(p.id)),
        Packet::Open(p) => ("OPEN", Some(p.id)),
        Packet::Close(p) => ("CLOSE", Some(p.id)),
        Packet::Read(p) => ("READ", Some(p.id)),
        Packet::Write(p) => ("WRITE", Some(p.id)),
        Packet::Lstat(p) => ("LSTAT", Some(p.id)),
        Packet::Fstat(p) => ("FSTAT", Some(p.id)),
        Packet::SetStat(p) => ("SETSTAT", Some(p.id)),
        Packet::FSetStat(p) => ("FSETSTAT", Some(p.id)),
        Packet::OpenDir(p) => ("OPENDIR", Some(p.id)),
        Packet::ReadDir(p) => ("READDIR", Some(p.id)),
        Packet::Remove(p) => ("REMOVE", Some(p.id)),
        Packet::MkDir(p) => ("MKDIR", Some(p.id)),
        Packet::RmDir(p) => ("RMDIR", Some(p.id)),
        Packet::RealPath(p) => ("REALPATH", Some(p.id)),
        Packet::Stat(p) => ("STAT", Some(p.id)),
        Packet::Rename(p) => ("RENAME", Some(p.id)),
        Packet::ReadLink(p) => ("READLINK", Some(p.id)),
        Packet::Symlink(p) => ("SYMLINK", Some(p.id)),
        Packet::Init(_) => ("INIT", None),
        Packet::Extended(p) => ("EXTENDED", Some(p.id)),
    }
}

macro_rules! into_wrap {
    ($handler:expr) => {
        match $handler.await {
            Err(error) => Err(error.into()),
            Ok(()) => Ok(()),
        }
    };
}

async fn execute_handler<H>(bytes: &mut Bytes, handler: &mut H) -> Result<(), error::Error>
where
    H: Handler + Send,
{
    let packet = Packet::try_from(bytes)?;
    let (packet_type, request_id) = packet_summary(&packet);
    info!(
        target: "sftp::rawsession_handler",
        "russh-sftp handler received packet: packet_type={} request_id={:?}",
        packet_type,
        request_id
    );

    match packet {
        Packet::Version(p) => into_wrap!(handler.version(p)),
        Packet::Status(p) => into_wrap!(handler.status(p)),
        Packet::Handle(p) => into_wrap!(handler.handle(p)),
        Packet::Data(p) => into_wrap!(handler.data(p)),
        Packet::Name(p) => into_wrap!(handler.name(p)),
        Packet::Attrs(p) => into_wrap!(handler.attrs(p)),
        Packet::ExtendedReply(p) => into_wrap!(handler.extended_reply(p)),
        _ => Err(error::Error::UnexpectedBehavior(
            "A packet was received that could not be processed.".to_owned(),
        )),
    }
}

async fn process_handler<S, H>(stream: &mut S, handler: &mut H) -> Result<(), Error>
where
    S: AsyncRead + Unpin,
    H: Handler + Send,
{
    let mut bytes = read_packet(stream).await?;
    Ok(execute_handler(&mut bytes, handler).await?)
}

/// Run processing stream as SFTP client. Is a simple handler of incoming
/// and outgoing packets. Can be used for non-standard implementations
pub fn run<S, H>(stream: S, mut handler: H) -> mpsc::UnboundedSender<Bytes>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: Handler + Send + 'static,
{
    let (tx, mut rx) = mpsc::unbounded_channel::<Bytes>();
    let (mut reader, mut writer) = tokio::io::split(stream);

    tokio::spawn(async move {
        let writer_task = tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                if data.is_empty() {
                    let _ = writer.shutdown().await;
                    break;
                }

                if let Err(err) = writer.write_all(&data[..]).await {
                    warn!("{}", err);
                    break;
                }
            }
        });

        loop {
            match process_handler(&mut reader, &mut handler).await {
                Err(Error::UnexpectedEof) => break,
                Err(err) => warn!("{}", err),
                Ok(_) => (),
            }
        }

        writer_task.abort();
        let _ = writer_task.await;
        debug!("sftp stream ended");
    });

    tx
}
