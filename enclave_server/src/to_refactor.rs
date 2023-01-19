/*
 * TODO: remove the dependency on the code in this module
 *
 * This is taked from here and modified:
 * https://github.com/kgraney/third-wheel/blob/attestation_support/src/proxy/mitm.rs
 */
use crate::error::Error;
use futures::Future;
use http::{header::HeaderName, Request, Response};
use hyper::{body::Incoming, client::conn::http1::SendRequest, service::Service};
use std::pin::Pin;
use tokio::sync::{mpsc, oneshot};
use tracing::error;

type ResponseSender = oneshot::Sender<Result<Response<Incoming>, Error>>;

pub(crate) struct RequestSendingSynchronizer {
    request_sender: SendRequest<Incoming>,
    receiver: mpsc::UnboundedReceiver<(ResponseSender, Request<Incoming>)>,
}

impl RequestSendingSynchronizer {
    pub(crate) const fn new(
        request_sender: SendRequest<Incoming>,
        receiver: mpsc::UnboundedReceiver<(ResponseSender, Request<Incoming>)>,
    ) -> Self {
        Self {
            request_sender,
            receiver,
        }
    }

    pub(crate) async fn run(&mut self) {
        while let Some((sender, mut request)) = self.receiver.recv().await {
            let relativized_uri = request
                .uri()
                .path_and_query()
                .ok_or_else(|| Error::RequestError("URI did not contain a path".to_string()))
                .and_then(|path| {
                    path.as_str()
                        .parse()
                        .map_err(|_| Error::RequestError("Given URI was invalid".to_string()))
                });
            let response_fut = relativized_uri.map(|path| {
                *request.uri_mut() = path;
                // TODO: don't have this unnecessary overhead every time
                let proxy_connection: HeaderName = HeaderName::from_lowercase(b"proxy-connection")
                    .expect("Infallible: hardcoded header name");
                request.headers_mut().remove(&proxy_connection);
                self.request_sender.send_request(request)
            });
            let response_to_send = match response_fut {
                Ok(response) => response.await.map_err(|e| e.into()),
                Err(e) => Err(e),
            };
            if let Err(e) = sender.send(response_to_send) {
                error!("Requester not available to receive request {:?}", e);
            }
        }
    }
}

/// A service that will proxy traffic to a target server and return unmodified responses
#[derive(Clone)]
pub struct ThirdWheel {
    sender: mpsc::UnboundedSender<(ResponseSender, Request<Incoming>)>,
}

impl ThirdWheel {
    pub(crate) const fn new(
        sender: mpsc::UnboundedSender<(ResponseSender, Request<Incoming>)>,
    ) -> Self {
        Self { sender }
    }
}

impl Service<Request<Incoming>> for ThirdWheel {
    type Response = Response<Incoming>;

    type Error = crate::error::Error;

    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    /// `ThirdWheel` performs very little modification of the request before
    /// transmitting it, but it does remove the proxy-connection header to
    /// ensure this is not passed to the target
    fn call(&mut self, request: Request<Incoming>) -> Self::Future {
        let (response_sender, response_receiver) = oneshot::channel();
        let sender = self.sender.clone();
        let fut = async move {
            //TODO: clarify what errors are possible here
            sender.send((response_sender, request)).map_err(|_| {
                Error::ProxyError("Failed to connect to server correctly".to_string())
            })?;
            response_receiver
                .await
                .map_err(|_| Error::ProxyError("Failed to get response from server".to_string()))?
        };
        Box::pin(fut)
    }
}
