//! Abstracts routing logic from the HTTP server

use std::{collections::HashMap, fmt::Display, marker::PhantomData};

use async_trait::async_trait;
use hyper::{Body, Request, Response, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/**
 * Helpers
 */

/// Builds an empty HTTP 400 (Bad Request) response
fn build_400_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::empty())
        .unwrap()
}

/// Builds an empty HTTP 404 (Not Found) response
fn build_404_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::empty())
        .unwrap()
}

/// Builds an empty HTTP 500 (Internal Server Error) response
fn build_500_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::empty())
        .unwrap()
}

/**
 * Trait implementations
 */

/// A handler is attached to a route and handles the process of translating an
/// abstract request type into a response
#[async_trait]
pub trait Handler {
    /// The handler method for the request/response on the handler's route
    async fn handle(&self, req: Request<Body>) -> Response<Body>;
}

/// A handler that has associated Request/Response type information attached to it.
/// We implement this as a subtrait so that the router can store trait objects
/// (associated types are disallowed on trait objects) as Handler that concretely
/// re-use the default serialization/deserialization logic below
pub trait TypedHandler: Send + Sync {
    /// The request type that the handler consumes
    type Request: DeserializeOwned + for<'de> Deserialize<'de>;
    /// The response type that the handler returns
    type Response: Serialize;
    /// The error type that the handler returns
    type Error: Display;

    /// The handler logic, translate request into response
    fn handle_typed(&self, req: Self::Request) -> Result<Self::Response, Self::Error>;
}

/// Auto-implementation of the Handler trait for a TypedHandler which covers the process
/// of deserializing the request, reporting errors, and serializing the response into a body
#[async_trait]
impl<
        Req: DeserializeOwned + for<'de> Deserialize<'de>,
        Resp: Serialize,
        E: Display,
        T: TypedHandler<Request = Req, Response = Resp, Error = E>,
    > Handler for T
{
    async fn handle(&self, req: Request<Body>) -> Response<Body> {
        // Deserialize the request into the request type, return HTTP 400 if deserialization fails
        let req_body_bytes = hyper::body::to_bytes(req.into_body()).await;
        if req_body_bytes.is_err() {
            return build_400_response();
        }

        let unwrapped: &[u8] = &req_body_bytes.unwrap(); // Necessary to explicitly hold temporary value
        let deserialized = serde_json::from_reader(unwrapped);
        if deserialized.is_err() {
            return build_400_response();
        }

        let req_body: Req = deserialized.unwrap();

        // Forward to the typed handler
        if let Ok(resp) = self.handle_typed(req_body) {
            // Serialize the response into a body
            Response::new(Body::from(serde_json::to_vec(&resp).unwrap()))
        } else {
            build_500_response()
        }
    }
}

/// A router handles the process of serialization/deserialization, and routing
/// to the appropriate handler
pub struct Router {
    /// The routing information, mapping endpoint to handler
    routes: HashMap<String, Box<dyn Handler>>,
}

impl Router {
    /// Create a new router with no routes established
    fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    /// Add a route to the router
    fn add_route<H: Handler + 'static>(&mut self, route: String, handler: H) {
        self.routes.insert(route, Box::new(handler));
    }

    /// Route a request to a handler
    async fn handle_req(&self, route: String, req: Request<Body>) -> Response<Body> {
        if let Some(handler) = self.routes.get(&route) {
            handler.as_ref().handle(req).await
        } else {
            build_404_response()
        }
    }
}
