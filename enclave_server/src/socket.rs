use std::io::Error;
use tokio::net::TcpListener;

pub async fn ipv4_listen(port: u16) -> Result<TcpListener, Error> {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    TcpListener::bind(&addr).await
}
