//! Primitives for listening on TCP and forwarding the data in incoming connections
//! to UDP.

use crate::exponential_backoff::ExponentialBackoff;
use crate::logging::Redact;
use err_context::ErrorExt as _;
use socket2::{Domain, Protocol, Socket, Type};
use std::convert::Infallible;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::sleep;

// Note: `futures::future::join_all` removed in favour of `tokio::task::JoinSet`.
// Note: `err_context::{BoxedErrorExt, ResultExt}` removed; `process_socket` now returns
//       a concrete `ProcessSocketError` instead of `Box<dyn Error>`.
// Note: `socket2::SockRef` removed from imports — set_reuse_port is commented out pending
//       `socket2 = { version = "0.5", features = ["all"] }` in Cargo.toml (see below).

#[path = "statsd.rs"]
mod statsd;

/// Settings for a tcp2udp session. This is the argument to [`run`] to
/// describe how the forwarding from TCP -> UDP should be set up.
///
/// This struct is `non_exhaustive` in order to allow adding more optional fields without
/// being considered breaking changes. So you need to create an instance via [`Options::new`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "clap", derive(clap::Parser))]
#[cfg_attr(feature = "clap", group(skip))]
#[non_exhaustive]
pub struct Options {
    /// The IP and TCP port(s) to listen to for incoming traffic from udp2tcp.
    /// Supports binding multiple TCP sockets.
    #[cfg_attr(feature = "clap", arg(long = "tcp-listen", required(true)))]
    pub tcp_listen_addrs: Vec<SocketAddr>,

    #[cfg_attr(feature = "clap", arg(long = "udp-forward"))]
    /// The IP and UDP port to forward all traffic to.
    pub udp_forward_addr: SocketAddr,

    /// Which local IP to bind the UDP socket to.
    #[cfg_attr(feature = "clap", arg(long = "udp-bind"))]
    pub udp_bind_ip: Option<IpAddr>,

    #[cfg_attr(feature = "clap", clap(flatten))]
    pub tcp_options: crate::tcp_options::TcpOptions,

    #[cfg(feature = "statsd")]
    /// Host to send statsd metrics to.
    #[cfg_attr(feature = "clap", clap(long))]
    pub statsd_host: Option<SocketAddr>,
}

impl Options {
    /// Creates a new [`Options`] with all mandatory fields set to the passed arguments.
    /// All optional values are set to their default values. They can later be set, since
    /// they are public.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, SocketAddr};
    ///
    /// let mut options = udp_over_tcp::tcp2udp::Options::new(
    ///     // Listen on 127.0.0.1:1234/TCP
    ///     vec![SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1234))],
    ///     // Forward to 192.0.2.15:5001/UDP
    ///     SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 15), 5001)),
    /// );
    ///
    /// // Bind the local UDP socket (used to send to 192.0.2.15:5001/UDP) to the loopback interface
    /// options.udp_bind_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    /// ```
    pub fn new(tcp_listen_addrs: Vec<SocketAddr>, udp_forward_addr: SocketAddr) -> Self {
        Options {
            tcp_listen_addrs,
            udp_forward_addr,
            udp_bind_ip: None,
            tcp_options: Default::default(),
            #[cfg(feature = "statsd")]
            statsd_host: None,
        }
    }
}

/// Error returned from [`run`] if something goes wrong.
#[derive(Debug)]
#[non_exhaustive]
pub enum Tcp2UdpError {
    /// No TCP listen addresses given in the `Options`.
    NoTcpListenAddrs,
    CreateTcpSocket(io::Error),
    /// Failed to apply TCP options to socket.
    ApplyTcpOptions(crate::tcp_options::ApplyTcpOptionsError),
    /// Failed to enable `SO_REUSEADDR` on TCP socket.
    SetReuseAddr(io::Error),
    /// Failed to bind TCP socket to SocketAddr
    BindTcpSocket(io::Error, SocketAddr),
    /// Failed to start listening on TCP socket
    ListenTcpSocket(io::Error, SocketAddr),
    #[cfg(feature = "statsd")]
    /// Failed to initialize statsd client
    CreateStatsdClient(statsd::Error),
}

impl fmt::Display for Tcp2UdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Tcp2UdpError::*;
        match self {
            NoTcpListenAddrs => "Invalid options, no TCP listen addresses".fmt(f),
            CreateTcpSocket(_) => "Failed to create TCP socket".fmt(f),
            ApplyTcpOptions(_) => "Failed to apply options to TCP socket".fmt(f),
            SetReuseAddr(_) => "Failed to set SO_REUSEADDR on TCP socket".fmt(f),
            BindTcpSocket(_, addr) => write!(f, "Failed to bind TCP socket to {}", addr),
            ListenTcpSocket(_, addr) => write!(
                f,
                "Failed to start listening on TCP socket bound to {}",
                addr
            ),
            #[cfg(feature = "statsd")]
            CreateStatsdClient(_) => "Failed to init metrics client".fmt(f),
        }
    }
}

impl std::error::Error for Tcp2UdpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Tcp2UdpError::*;
        match self {
            NoTcpListenAddrs => None,
            CreateTcpSocket(e) => Some(e),
            ApplyTcpOptions(e) => Some(e),
            SetReuseAddr(e) => Some(e),
            BindTcpSocket(e, _) => Some(e),
            ListenTcpSocket(e, _) => Some(e),
            #[cfg(feature = "statsd")]
            CreateStatsdClient(e) => Some(e),
        }
    }
}

/// Concrete error type for per-connection UDP socket setup in [`process_socket`].
/// Replaces `Box<dyn std::error::Error>` to avoid a heap allocation on every error path.
#[derive(Debug)]
enum ProcessSocketError {
    BindUdp(io::Error),
    ConnectUdp(io::Error),
}

impl fmt::Display for ProcessSocketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BindUdp(_) => "Failed to bind UDP socket".fmt(f),
            Self::ConnectUdp(_) => "Failed to connect UDP socket to peer".fmt(f),
        }
    }
}

impl std::error::Error for ProcessSocketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BindUdp(e) | Self::ConnectUdp(e) => Some(e),
        }
    }
}

/// Sets up TCP listening sockets on all addresses in `Options::tcp_listen_addrs`.
/// If binding a listening socket fails this returns an error. Otherwise the function
/// will continue indefinitely to accept incoming connections and forward to UDP.
/// Errors are just logged.
pub async fn run(options: Options) -> Result<Infallible, Tcp2UdpError> {
    if options.tcp_listen_addrs.is_empty() {
        return Err(Tcp2UdpError::NoTcpListenAddrs);
    }

    let udp_bind_ip = options.udp_bind_ip.unwrap_or_else(|| {
        if options.udp_forward_addr.is_ipv4() {
            "0.0.0.0".parse().unwrap()
        } else {
            "::".parse().unwrap()
        }
    });

    #[cfg(not(feature = "statsd"))]
    let statsd = Arc::new(statsd::StatsdMetrics::dummy());
    #[cfg(feature = "statsd")]
    let statsd = Arc::new(match options.statsd_host {
        None => statsd::StatsdMetrics::dummy(),
        Some(statsd_host) => {
            statsd::StatsdMetrics::real(statsd_host).map_err(Tcp2UdpError::CreateStatsdClient)?
        }
    });

    // JoinSet replaces `Vec<JoinHandle> + futures::future::join_all`:
    //   - reaps completed tasks immediately instead of holding all handles until every task ends
    //   - surfaces per-task panics individually so they can be logged rather than silently dropped
    let mut set = JoinSet::new();
    for tcp_listen_addr in options.tcp_listen_addrs {
        let tcp_listener = create_listening_socket(tcp_listen_addr, &options.tcp_options)?;
        log::info!("Listening on {}/TCP", tcp_listener.local_addr().unwrap());

        let udp_forward_addr = options.udp_forward_addr;
        let tcp_recv_timeout = options.tcp_options.recv_timeout;
        let tcp_nodelay = options.tcp_options.nodelay;
        let statsd = Arc::clone(&statsd);
        set.spawn(async move {
            process_tcp_listener(
                tcp_listener,
                udp_bind_ip,
                udp_forward_addr,
                tcp_recv_timeout,
                tcp_nodelay,
                statsd,
            )
            .await;
        });
    }

    while let Some(res) = set.join_next().await {
        match res {
            Ok(_) => unreachable!("Listener tasks run forever"),
            Err(e) => log::error!("Listener task panicked: {:?}", e),
        }
    }
    unreachable!("Listening TCP sockets never exit");
}

fn create_listening_socket(
    addr: SocketAddr,
    options: &crate::tcp_options::TcpOptions,
) -> Result<TcpListener, Tcp2UdpError> {
    let tcp_socket = match addr {
        SocketAddr::V4(..) => TcpSocket::new_v4(),
        SocketAddr::V6(..) => TcpSocket::new_v6(),
    }
    .map_err(Tcp2UdpError::CreateTcpSocket)?;

    crate::tcp_options::apply(&tcp_socket, options).map_err(Tcp2UdpError::ApplyTcpOptions)?;

    tcp_socket
        .set_reuseaddr(true)
        .map_err(Tcp2UdpError::SetReuseAddr)?;

    // TO ENABLE SO_REUSEPORT (lets the kernel distribute connections across all Tokio
    // worker threads, removing the single-core accept bottleneck): add
    // `socket2 = { version = "0.5", features = ["all"] }` to Cargo.toml, add
    // `use socket2::SockRef;` to the imports, then uncomment the following block:
    //
    // #[cfg(unix)]
    // SockRef::from(&tcp_socket)
    //     .set_reuse_port(true)
    //     .map_err(Tcp2UdpError::SetReuseAddr)?;

    // Accepted TcpStreams inherit buffer sizes from the listener socket, so tuning here
    // covers every future connection without per-stream syscalls.
    tcp_socket
        .set_recv_buffer_size(256 * 1024)
        .map_err(Tcp2UdpError::CreateTcpSocket)?;
    tcp_socket
        .set_send_buffer_size(256 * 1024)
        .map_err(Tcp2UdpError::CreateTcpSocket)?;

    tcp_socket
        .bind(addr)
        .map_err(|e| Tcp2UdpError::BindTcpSocket(e, addr))?;

    // Backlog raised from 1024 to 4096: under DNS burst traffic the kernel silently
    // drops incoming SYNs with RST when the queue fills, causing client-side retries.
    let tcp_listener = tcp_socket
        .listen(4096)
        .map_err(|e| Tcp2UdpError::ListenTcpSocket(e, addr))?;

    Ok(tcp_listener)
}

async fn process_tcp_listener(
    tcp_listener: TcpListener,
    udp_bind_ip: IpAddr,
    udp_forward_addr: SocketAddr,
    tcp_recv_timeout: Option<Duration>,
    tcp_nodelay: bool,
    statsd: Arc<statsd::StatsdMetrics>,
) -> ! {
    let mut cooldown =
        ExponentialBackoff::new(Duration::from_millis(50), Duration::from_millis(5000));
    loop {
        match tcp_listener.accept().await {
            Ok((tcp_stream, tcp_peer_addr)) => {
                log::debug!("Incoming connection from {}/TCP", Redact(tcp_peer_addr));
                let statsd = statsd.clone();
                tokio::spawn(async move {
                    // set_nodelay is inside the spawned task so the accept loop is never
                    // stalled by a syscall before it can call accept() again.
                    if let Err(error) = crate::tcp_options::set_nodelay(&tcp_stream, tcp_nodelay) {
                        log::error!("Error: {}", error.display("\nCaused by: "));
                    }
                    statsd.incr_connections();
                    if let Err(error) = process_socket(
                        tcp_stream,
                        tcp_peer_addr,
                        udp_bind_ip,
                        udp_forward_addr,
                        tcp_recv_timeout,
                    )
                    .await
                    {
                        log::error!("Error: {}", error.display("\nCaused by: "));
                    }
                    statsd.decr_connections();
                });
                cooldown.reset();
            }
            Err(error) => {
                log::error!("Error when accepting incoming TCP connection: {}", error);

                statsd.accept_error();

                // If the process runs out of file descriptors, it will fail to accept a socket.
                // But that socket will also remain in the queue, so it will fail again immediately.
                // This will busy loop consuming the CPU and filling any logs. To prevent this,
                // delay between failed socket accept operations.
                sleep(cooldown.next_delay()).await;
            }
        }
    }
}

/// Sets up a UDP socket bound to `udp_bind_ip` and connected to `udp_peer_addr` and forwards
/// traffic between that UDP socket and the given `tcp_stream` until the `tcp_stream` is closed.
/// `tcp_peer_addr` should be the remote addr that `tcp_stream` is connected to.
async fn process_socket(
    tcp_stream: TcpStream,
    tcp_peer_addr: SocketAddr,
    udp_bind_ip: IpAddr,
    udp_peer_addr: SocketAddr,
    tcp_recv_timeout: Option<Duration>,
) -> Result<(), ProcessSocketError> {
    let udp_bind_addr = SocketAddr::new(udp_bind_ip, 0);

    // socket2 is used here because tokio's UdpSocket::bind does not expose SO_RCVBUF /
    // SO_SNDBUF. Larger buffers reduce kernel-side packet drops under burst traffic.
    let domain = match udp_bind_addr {
        SocketAddr::V4(..) => Domain::IPV4,
        SocketAddr::V6(..) => Domain::IPV6,
    };
    let raw_udp = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(ProcessSocketError::BindUdp)?;
    raw_udp
        .set_recv_buffer_size(512 * 1024)
        .map_err(ProcessSocketError::BindUdp)?;
    raw_udp
        .set_send_buffer_size(512 * 1024)
        .map_err(ProcessSocketError::BindUdp)?;
    raw_udp
        .set_nonblocking(true)
        .map_err(ProcessSocketError::BindUdp)?;
    raw_udp
        .bind(&udp_bind_addr.into())
        .map_err(ProcessSocketError::BindUdp)?;

    let udp_socket =
        UdpSocket::from_std(raw_udp.into()).map_err(ProcessSocketError::BindUdp)?;

    udp_socket
        .connect(udp_peer_addr)
        .await
        .map_err(ProcessSocketError::ConnectUdp)?;

    match udp_socket.local_addr() {
        Ok(local) => log::debug!("UDP socket bound to {} -> {}", local, udp_peer_addr),
        Err(_) => log::debug!("UDP socket connected to {}", udp_peer_addr),
    }

    crate::forward_traffic::process_udp_over_tcp(udp_socket, tcp_stream, tcp_recv_timeout).await;
    log::debug!(
        "Closing forwarding for {}/TCP <-> {}/UDP",
        Redact(tcp_peer_addr),
        udp_peer_addr
    );

    Ok(())
}
