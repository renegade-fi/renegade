//! Abstracts routing logic from the HTTP server

use std::collections::HashMap;

use async_trait::async_trait;
use hyper::{Body, Method, Request, Response, StatusCode};
use matchit::Router as MatchRouter;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::log;

use super::error::ApiServerError;

/// A type alias for URL generic params maps, i.e. /path/to/resource/:id
pub(super) type UrlParams = HashMap<String, String>;

// -----------
// | Helpers |
// -----------

/// Builds an empty HTTP 400 (Bad Request) response
pub(super) fn build_400_response(err: String) -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::from(err))
        .unwrap()
}

/// Builds an empty HTTP 404 (Not Found) response
pub(super) fn build_404_response(err: String) -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from(err))
        .unwrap()
}

/// Builds an empty HTTP 500 (Internal Server Error) response
pub(super) fn build_500_response(err: String) -> Response<Body> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from(err))
        .unwrap()
}

/// Builds an empty HTTP XXX response
pub(super) fn build_response_from_status_code(
    status_code: StatusCode,
    err: String,
) -> Response<Body> {
    Response::builder()
        .status(status_code)
        .body(Body::from(err))
        .unwrap()
}

// -------------------------
// | Trait Implementations |
// -------------------------

/// A handler is attached to a route and handles the process of translating an
/// abstract request type into a response
#[async_trait]
pub trait Handler: Send + Sync {
    /// The handler method for the request/response on the handler's route
    async fn handle(&self, req: Request<Body>, url_params: UrlParams) -> Response<Body>;
}

/// A handler that has associated Request/Response type information attached to it.
/// We implement this as a subtrait so that the router can store trait objects
/// (associated types are disallowed on trait objects) as Handler that concretely
/// re-use the default serialization/deserialization logic below
#[async_trait]
pub trait TypedHandler: Send + Sync {
    /// The request type that the handler consumes
    type Request: DeserializeOwned + for<'de> Deserialize<'de>;
    /// The response type that the handler returns
    type Response: Serialize + Send;

    /// The handler logic, translate request into response
    async fn handle_typed(
        &self,
        req: Self::Request,
        url_params: UrlParams,
    ) -> Result<Self::Response, ApiServerError>;
}

/// Auto-implementation of the Handler trait for a TypedHandler which covers the process
/// of deserializing the request, reporting errors, and serializing the response into a body
#[async_trait]
impl<
        Req: DeserializeOwned + for<'de> Deserialize<'de> + Send,
        Resp: Serialize,
        T: TypedHandler<Request = Req, Response = Resp>,
    > Handler for T
{
    async fn handle(&self, req: Request<Body>, url_params: UrlParams) -> Response<Body> {
        // Deserialize the request into the request type, return HTTP 400 if deserialization fails
        let req_body_bytes = hyper::body::to_bytes(req.into_body()).await;
        if let Err(e) = req_body_bytes {
            return build_400_response(e.to_string());
        }

        let mut unwrapped: &[u8] = &req_body_bytes.unwrap(); // Necessary to explicitly hold temporary value
        if unwrapped.is_empty() {
            // If no HTTP body data was passed, replace the data with "null". Serde expects "null" as
            // the serialized version of an empty struct
            unwrapped = "null".as_bytes();
        }
        let deserialized = serde_json::from_reader(unwrapped);
        if let Err(e) = deserialized {
            return build_400_response(e.to_string());
        }

        let req_body: Req = deserialized.unwrap();

        // Forward to the typed handler
        let res = self.handle_typed(req_body, url_params).await;
        if let Ok(resp) = res {
            // Serialize the response into a body. We explicitly allow for all cross-origin
            // requests, as users connecting to a locally-run node have a different origin port.

            // TODO: Either remove this in the future, or ensure that no sensitive information can
            // leak from cross-origin requests.
            Response::builder()
                .header("Access-Control-Allow-Origin", "*")
                .body(Body::from(serde_json::to_vec(&resp).unwrap()))
                .unwrap()
        } else {
            let err = res.err().unwrap();
            match err.clone() {
                ApiServerError::HttpStatusCode(status, message) => {
                    build_response_from_status_code(status, message)
                }
                _ => build_500_response(err.to_string()),
            }
        }
    }
}

/// Wrapper around a matchit router that allows different HTTP request types to be matches
///
pub struct Router {
    /// The underlying router
    router: MatchRouter<Box<dyn Handler>>,
}

impl Router {
    /// Create a new router with no routes established
    pub fn new() -> Self {
        let router = MatchRouter::new();
        Self { router }
    }

    /// Helper to build a routable path from a method and a concrete route
    ///
    /// The `matchit::Router` works only on URLs directly; so we prepend the
    /// path to the URL when creating the route
    ///
    /// Concretely, if POST is valid to /route then we route to /POST/route
    fn create_full_route(method: Method, mut route: String) -> String {
        // Prepend a "/" if not already done
        if !route.starts_with('/') {
            route = String::from("/") + &route;
        }

        // Matchit is URL only, so we prepend the request type to match directly
        let method_str = method.to_string();
        format!("/{}{}", method_str, route)
    }

    /// Add a route to the router
    pub fn add_route<H: Handler + 'static>(&mut self, method: Method, route: String, handler: H) {
        log::debug!("Attached handler to route {route} with method {method}");
        let full_route = Self::create_full_route(method, route);

        self.router
            .insert(full_route, Box::new(handler))
            .expect("error attaching handler to route");
    }

    /// Route a request to a handler
    pub async fn handle_req(
        &self,
        method: Method,
        route: String,
        req: Request<Body>,
    ) -> Response<Body> {
        // Get the full routable path
        let full_route = Self::create_full_route(method.clone(), route.clone());

        // Dispatch to handler
        if let Ok(matched_path) = self.router.at(&full_route) {
            let handler = matched_path.value;
            let params = matched_path.params;

            // Clone the params to take ownership
            let mut params_map = HashMap::with_capacity(params.len());
            for (key, value) in params.iter() {
                params_map.insert(key.to_string(), value.to_string());
            }

            handler.as_ref().handle(req, params_map).await
        } else {
            build_404_response(format!("Route {} for method {} not found", route, method))
        }
    }
}
