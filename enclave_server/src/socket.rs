use std::io::Error;
use tokio::net::TcpListener;
use tokio_vsock::VsockListener;

pub async fn ipv4_listen(port: u16) -> Result<TcpListener, Error> {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    TcpListener::bind(&addr).await
}

pub async fn vsock_listen(cid: u32, port: u32) -> Result<VsockListener, Error> {
    VsockListener::bind(cid, port)
}
