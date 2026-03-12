use bytes::{BufMut, Bytes, BytesMut};
use err_context::BoxedErrorExt as _;
use err_context::ResultExt as _;
use socket2::Socket;
use std::io;
use std::mem;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::tcp::{OwnedReadHalf as TcpReadHalf, OwnedWriteHalf as TcpWriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::timeout;

pub const MAX_DATAGRAM_SIZE: usize = u16::MAX as usize;
pub const HEADER_LEN: usize = mem::size_of::<u16>();

/// Forward traffic between the given UDP and TCP sockets in both directions.
/// This async function runs until one of the sockets is closed or there is an error.
pub async fn process_udp_over_tcp(
    udp_socket: UdpSocket,
    tcp_stream: TcpStream,
    tcp_recv_timeout: Option<Duration>,
) {
    // 1. Buffer Size Improvements using socket2
    let std_udp = udp_socket.into_std().expect("Failed to get std socket");
    
    // Convert to socket2::Socket to access OS-level buffer tuning
    let sock = Socket::from(std_udp);
    let _ = sock.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = sock.set_send_buffer_size(4 * 1024 * 1024);
    let _ = sock.set_nonblocking(true); // Ensure it stays non-blocking for tokio
    
    // Convert back down to std::net::UdpSocket, then to tokio::net::UdpSocket
    let std_udp: std::net::UdpSocket = sock.into();
    let udp_socket = UdpSocket::from_std(std_udp).expect("Failed to restore tokio socket");

    // Disable Nagle's algorithm to reduce latency for small UDP datagrams
    tcp_stream.set_nodelay(true).expect("set_nodelay failed");

    let udp_in = Arc::new(udp_socket);
    let udp_out = udp_in.clone();
    let (tcp_in, tcp_out) = tcp_stream.into_split();

    let mut tcp2udp_handle = tokio::spawn(async move {
        if let Err(error) = process_tcp2udp(tcp_in, udp_out, tcp_recv_timeout).await {
            log::error!("TCP->UDP Error: {}", error.display("\nCaused by: "));
        }
    });

    let mut udp2tcp_handle = tokio::spawn(async move {
        if let Err(error) = process_udp2tcp(udp_in, tcp_out).await {
            log::error!("UDP->TCP Error: {}", error.display("\nCaused by: "));
        }
    });

    // Wait until either task terminates, then abort the other to clean up resources.
    tokio::select! {
        _ = &mut tcp2udp_handle => { udp2tcp_handle.abort(); },
        _ = &mut udp2tcp_handle => { tcp2udp_handle.abort(); },
    }
}

async fn process_tcp2udp(
    tcp_in: TcpReadHalf,
    udp_out: Arc<UdpSocket>,
    tcp_recv_timeout: Option<Duration>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Keep this as BufReader/read_exact. It re-uses a single allocation (datagram_buffer)
    // for all TCP -> UDP reads, making it already zero-allocation.
    let mut tcp_in = BufReader::with_capacity(256 * 1024, tcp_in);
    let mut header_buf = [0u8; HEADER_LEN];
    let mut buffer = datagram_buffer();

    loop {
        let result = maybe_timeout(tcp_recv_timeout, tcp_in.read_exact(&mut header_buf))
            .await
            .context("Timeout while reading from TCP")?;

        match result {
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            r => { r.context("Failed reading from TCP")?; }
        }

        let datagram_len = usize::from(u16::from_be_bytes(header_buf));

        maybe_timeout(
            tcp_recv_timeout,
            tcp_in.read_exact(&mut buffer[..datagram_len]),
        )
        .await
        .context("Timeout while reading from TCP")?
        .context("Failed reading from TCP")?;

        let udp_write_len = udp_out
            .send(&buffer[..datagram_len])
            .await
            .context("Failed writing to UDP")?;
            
        assert_eq!(udp_write_len, datagram_len, "Did not send entire UDP datagram");
        log::trace!("Forwarded {} bytes TCP->UDP", datagram_len);
    }

    log::debug!("TCP socket closed");
    Ok(())
}

async fn maybe_timeout<F: std::future::Future>(
    duration: Option<Duration>,
    future: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    match duration {
        Some(duration) => timeout(duration, future).await,
        None => Ok(future.await),
    }
}

async fn process_udp2tcp(
    udp_in: Arc<UdpSocket>,
    tcp_out: TcpWriteHalf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 2. Zero-Copy Bytes Channel
    let (tx, mut rx) = mpsc::channel::<Bytes>(1024);

    let udp_reader = {
        let udp_in = udp_in.clone();
        tokio::spawn(async move {
            let mut buf = BytesMut::with_capacity(64 * 1024);
            loop {
                // Ensure we have enough contiguous space for a max datagram + header
                buf.reserve(HEADER_LEN + MAX_DATAGRAM_SIZE);
                
                // Put a 2-byte placeholder for our length header
                buf.put_u16(0);
                
                // recv_buf writes directly into the uninitialized tail of our memory block
                match udp_in.recv_buf(&mut buf).await {
                    Ok(n) => {
                        let datagram_len = u16::try_from(n).expect("UDP datagram too large");
                        
                        // Overwrite the 2-byte placeholder at the start of our current chunk
                        buf[0..HEADER_LEN].copy_from_slice(&datagram_len.to_be_bytes());
                        
                        // 3. Zero-Copy Split & Freeze
                        // .split() takes the chunk we just wrote and leaves `buf` empty for the next loop
                        // .freeze() safely hands a reference-counted pointer into our mpsc channel
                        let packet = buf.split().freeze();
                        
                        // 4. Intelligent Backpressure Handling
                        if let Err(mpsc::error::TrySendError::Full(_)) = tx.try_send(packet) {
                            log::warn!("TCP connection congested: Dropped incoming UDP datagram");
                        }
                    }
                    Err(e) => {
                        log::error!("Failed reading from UDP: {}", e);
                        break;
                    }
                }
            }
        })
    };

    let mut tcp_out = BufWriter::with_capacity(256 * 1024, tcp_out);
    
    // Read the first packet from the channel, blocking if empty
    while let Some(packet) = rx.recv().await {
        tcp_out.write_all(&packet).await.context("Failed writing to TCP")?;
        
        // 5. Smart Latency Flushing
        // Drain all immediately available packets before triggering a flush
        while let Ok(next_packet) = rx.try_recv() {
            tcp_out.write_all(&next_packet).await.context("Failed writing to TCP")?;
        }
        
        tcp_out.flush().await.context("Failed flushing TCP")?;
    }

    udp_reader.abort();
    Ok(())
}

#[inline(never)]
pub fn datagram_buffer() -> Box<[u8; MAX_DATAGRAM_SIZE]> {
    Box::new([0u8; MAX_DATAGRAM_SIZE])
}
