//! Primitives for listening on UDP and forwarding the data in incoming datagrams
//! to a TCP stream.

use crate::logging::Redact;
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpSocket, UdpSocket};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Failed to create the TCP socket.
    CreateTcpSocket(io::Error),
    /// Failed to apply the given TCP socket options.
    ApplyTcpOptions(crate::tcp_options::ApplyTcpOptionsError),
    /// Failed to bind UDP socket locally.
    BindUdp(io::Error),
    /// Failed to read from UDP socket.
    ReadUdp(io::Error),
    /// Failed to connect UDP socket to the incoming address.
    ConnectUdp(io::Error),
    /// Failed to connect TCP socket to forward address.
    ConnectTcp(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            CreateTcpSocket(_) => "Failed to create the TCP socket".fmt(f),
            ApplyTcpOptions(e) => e.fmt(f),
            BindUdp(_) => "Failed to bind UDP socket locally".fmt(f),
            ReadUdp(_) => "Failed receiving the first UDP datagram".fmt(f),
            ConnectUdp(_) => "Failed to connect UDP socket to peer".fmt(f),
            ConnectTcp(_) => "Failed to connect to TCP forward address".fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;
        match self {
            CreateTcpSocket(e) => Some(e),
            ApplyTcpOptions(e) => e.source(),
            BindUdp(e) => Some(e),
            ReadUdp(e) => Some(e),
            ConnectUdp(e) => Some(e),
            ConnectTcp(e) => Some(e),
        }
    }
}

/// Struct allowing listening on UDP and forwarding the traffic over TCP.
pub struct Udp2Tcp {
    tcp_socket: TcpSocket,
    udp_socket: UdpSocket,
    tcp_forward_addr: SocketAddr,
    tcp_options: crate::TcpOptions,
}

impl Udp2Tcp {
    /// Creates a TCP socket and binds to the given UDP address.
    /// Just calling this constructor won't forward any traffic over the sockets (see `run`).
    pub async fn new(
        udp_listen_addr: SocketAddr,
        tcp_forward_addr: SocketAddr,
        tcp_options: crate::TcpOptions,
    ) -> Result<Self, Error> {
        // --- TCP socket setup ---
        let tcp_socket = match &tcp_forward_addr {
            SocketAddr::V4(..) => TcpSocket::new_v4(),
            SocketAddr::V6(..) => TcpSocket::new_v6(),
        }
        .map_err(Error::CreateTcpSocket)?;

        // Apply user-defined TCP options (keepalive, etc.) before connecting.
        crate::tcp_options::apply(&tcp_socket, &tcp_options).map_err(Error::ApplyTcpOptions)?;

        // Set TCP_NODELAY on the pre-connect socket via socket2 so the very first
        // segment after the handshake is sent without Nagle delay.
        if tcp_options.nodelay {
            SockRef::from(&tcp_socket)
                .set_tcp_nodelay(true)
                .map_err(Error::CreateTcpSocket)?;
        }

        // Increase TCP socket buffers beyond OS defaults for higher throughput.
        tcp_socket
            .set_recv_buffer_size(256 * 1024)
            .map_err(Error::CreateTcpSocket)?;
        tcp_socket
            .set_send_buffer_size(256 * 1024)
            .map_err(Error::CreateTcpSocket)?;

        // --- UDP socket setup via socket2 for SO_REUSEPORT and buffer tuning ---
        let domain = match &udp_listen_addr {
            SocketAddr::V4(..) => Domain::IPV4,
            SocketAddr::V6(..) => Domain::IPV6,
        };
        let raw_udp =
            Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(Error::BindUdp)?;

        raw_udp.set_reuse_address(true).map_err(Error::BindUdp)?;
        // SO_REUSEPORT allows multiple tasks to share the socket fd, enabling
        // concurrent datagram dispatch across Tokio worker threads.
        #[cfg(unix)]
        raw_udp.set_reuse_port(true).map_err(Error::BindUdp)?;

        // Larger UDP buffers reduce kernel-side packet drops under burst traffic.
        raw_udp
            .set_recv_buffer_size(512 * 1024)
            .map_err(Error::BindUdp)?;
        raw_udp
            .set_send_buffer_size(512 * 1024)
            .map_err(Error::BindUdp)?;

        raw_udp.set_nonblocking(true).map_err(Error::BindUdp)?;
        raw_udp
            .bind(&udp_listen_addr.into())
            .map_err(Error::BindUdp)?;

        let udp_socket = UdpSocket::from_std(raw_udp.into()).map_err(Error::BindUdp)?;

        match udp_socket.local_addr() {
            Ok(addr) => log::info!("Listening on {}/UDP", addr),
            Err(e) => log::error!("Unable to get UDP local addr: {}", e),
        }

        Ok(Self {
            tcp_socket,
            udp_socket,
            tcp_forward_addr,
            tcp_options,
        })
    }

    /// Returns the UDP address this instance is listening on for incoming datagrams to forward.
    ///
    /// Useful to call if `Udp2Tcp::new` was given port zero in `udp_listen_addr` to let the OS
    /// pick a random port. Then this method will return the actual port it is now bound to.
    pub fn local_udp_addr(&self) -> io::Result<SocketAddr> {
        self.udp_socket.local_addr()
    }

    /// Returns the raw file descriptor for the TCP socket that datagrams are forwarded to.
    #[cfg(unix)]
    pub fn remote_tcp_fd(&self) -> RawFd {
        self.tcp_socket.as_raw_fd()
    }

    /// Connects to the TCP address and runs the forwarding until the TCP socket is closed, or
    /// an error occur.
    pub async fn run(self) -> Result<(), Error> {
        let Self {
            tcp_socket,
            udp_socket,
            tcp_forward_addr,
            tcp_options,
        } = self;

        let mut tmp_buffer = crate::forward_traffic::datagram_buffer();

        // Concurrently wait for the first UDP datagram AND establish the TCP connection.
        // Previously these were sequential: peek_from (syscall #1) -> TCP connect -> re-read
        // (syscall #2 inside process_udp_over_tcp). Now we do both in parallel with a single
        // real recv_from, saving one full TCP RTT and one redundant syscall per session.
        log::debug!("Connecting to {}/TCP", tcp_forward_addr);
        let (tcp_result, udp_result) = tokio::join!(
            tcp_socket.connect(tcp_forward_addr),
            udp_socket.recv_from(tmp_buffer.as_mut())
        );

        let tcp_stream = tcp_result.map_err(Error::ConnectTcp)?;
        let (first_datagram_len, udp_peer_addr) = udp_result.map_err(Error::ReadUdp)?;

        log::debug!("Incoming connection from {}/UDP", Redact(udp_peer_addr));
        log::debug!("Connected to {}/TCP", tcp_forward_addr);

        // Belt-and-suspenders: also set TCP_NODELAY on the live TcpStream in case the
        // pre-connect SockRef call was not honoured by the OS.
        crate::tcp_options::set_nodelay(&tcp_stream, tcp_options.nodelay)
            .map_err(Error::ApplyTcpOptions)?;

        // Connect the UDP socket to whoever sent the first datagram. All return
        // traffic will be directed back to this peer.
        udp_socket
            .connect(udp_peer_addr)
            .await
            .map_err(Error::ConnectUdp)?;

        // Pass the already-read first datagram directly so process_udp_over_tcp does not
        // need to re-read it. Requires the updated signature:
        //   process_udp_over_tcp(udp, tcp, timeout, first_datagram: Option<&[u8]>)
        crate::forward_traffic::process_udp_over_tcp(
            udp_socket,
            tcp_stream,
            tcp_options.recv_timeout,
            Some(&tmp_buffer[..first_datagram_len]),
        )
        .await;

        log::debug!(
            "Closing forwarding for {}/UDP <-> {}/TCP",
            Redact(udp_peer_addr),
            tcp_forward_addr,
        );

        Ok(())
    }
}
