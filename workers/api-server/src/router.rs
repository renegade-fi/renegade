//! Abstracts routing logic from the HTTP server

use std::{collections::HashMap, iter};

use async_trait::async_trait;
use common::types::gossip::SymmetricAuthKey;
use hyper::{body::to_bytes, Body, HeaderMap, Method, Request, Response, StatusCode, Uri};
use itertools::Itertools;
use matchit::Router as MatchRouter;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use state::State;
use tracing::{debug, instrument, warn};

use crate::{
    auth::{AuthMiddleware, AuthType},
    error::bad_request,
};

use super::{error::ApiServerError, http::parse_wallet_id_from_params};

/// A type alias for URL generic params maps, i.e. /path/to/resource/:id
pub(super) type UrlParams = HashMap<String, String>;
/// A type alias for query params, i.e. /path/to/resource?id=123
pub(super) type QueryParams = HashMap<String, String>;

/// The maximum time an OPTIONS request to our HTTP API may be cached, we go
/// above the default of 5 seconds to avoid unnecessary pre-flights
const PREFLIGHT_CACHE_TIME: &str = "7200"; // 2 hours, Chromium max
/// Error message displayed when a wallet cannot be found in the global state
pub(super) const ERR_WALLET_NOT_FOUND: &str = "wallet not found";
/// Error message returned when query params are invalid
const ERR_INVALID_QUERY_PARAMS: &str = "invalid query params";

// -----------
// | Helpers |
// -----------

/// Builds an empty HTTP 400 (Bad Request) response
pub(super) fn build_400_response(err: String) -> Response<Body> {
    build_response_from_status_code(StatusCode::BAD_REQUEST, err)
}

/// Builds an empty HTTP 404 (Not Found) response
pub(super) fn build_404_response(err: String) -> Response<Body> {
    build_response_from_status_code(StatusCode::NOT_FOUND, err)
}

/// Builds an empty HTTP 500 (Internal Server Error) response
pub(super) fn build_500_response(err: String) -> Response<Body> {
    build_response_from_status_code(StatusCode::INTERNAL_SERVER_ERROR, err)
}

/// Builds an empty HTTP XXX response
pub(super) fn build_response_from_status_code(
    status_code: StatusCode,
    err: String,
) -> Response<Body> {
    Response::builder()
        .status(status_code)
        .header("Access-Control-Allow-Origin", "*")
        .body(Body::from(err))
        .unwrap()
}

/// Parse key value pairs from query params string
fn parse_query_params(query_str: &str) -> Result<QueryParams, &'static str> {
    if query_str.is_empty() {
        return Ok(QueryParams::new());
    }

    let mut params = QueryParams::new();
    for param in query_str.split('&') {
        let (key, value) = param.split_once('=').ok_or(ERR_INVALID_QUERY_PARAMS)?;
        params.insert(key.to_string(), value.to_string());
    }

    Ok(params)
}

// -------------------------
// | Trait Implementations |
// -------------------------

/// A handler is attached to a route and handles the process of translating an
/// abstract request type into a response
#[async_trait]
pub trait Handler: Send + Sync {
    /// The handler method for the request/response on the handler's route
    async fn handle(
        &self,
        req: Request<Body>,
        url_params: UrlParams,
        query_params: QueryParams,
    ) -> Response<Body>;
}

/// A handler that has associated Request/Response type information attached to
/// it. We implement this as a subtrait so that the router can store trait
/// objects (associated types are disallowed on trait objects) as Handler that
/// concretely re-use the default serialization/deserialization logic below
#[async_trait]
pub trait TypedHandler: Send + Sync {
    /// The request type that the handler consumes
    type Request: DeserializeOwned + for<'de> Deserialize<'de>;
    /// The response type that the handler returns
    type Response: Serialize + Send;

    /// The handler logic, translate request into response
    async fn handle_typed(
        &self,
        headers: HeaderMap,
        req: Self::Request,
        url_params: UrlParams,
        query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError>;
}

/// Auto-implementation of the Handler trait for a TypedHandler which covers the
/// process of deserializing the request, reporting errors, and serializing the
/// response into a body
#[async_trait]
impl<
        Req: DeserializeOwned + for<'de> Deserialize<'de> + Send,
        Resp: Serialize,
        T: TypedHandler<Request = Req, Response = Resp>,
    > Handler for T
{
    async fn handle(
        &self,
        req: Request<Body>,
        url_params: UrlParams,
        query_params: QueryParams,
    ) -> Response<Body> {
        // Copy the headers before consuming the body
        let headers = req.headers().clone();

        // Deserialize the request into the request type, return HTTP 400 if
        // deserialization fails
        let req_body_bytes = hyper::body::to_bytes(req.into_body()).await;
        if let Err(e) = req_body_bytes {
            return build_400_response(e.to_string());
        }

        let mut unwrapped: &[u8] = &req_body_bytes.unwrap(); // Necessary to explicitly hold temporary value
        if unwrapped.is_empty() {
            // If no HTTP body data was passed, replace the data with "null". Serde expects
            // "null" as the serialized version of an empty struct
            unwrapped = "null".as_bytes();
        }
        let deserialized = serde_json::from_reader(unwrapped);
        if let Err(e) = deserialized {
            return build_400_response(e.to_string());
        }

        let req_body: Req = deserialized.unwrap();

        // Forward to the typed handler
        let res = self.handle_typed(headers, req_body, url_params, query_params).await;
        let builder = Response::builder().header("Access-Control-Allow-Origin", "*");
        match res {
            Ok(resp) => {
                // Serialize the response into a body. We explicitly allow for all cross-origin
                // requests, as users connecting to a locally-run node have a different origin
                // port.

                // TODO: Either remove this in the future, or ensure that no sensitive
                // information can leak from cross-origin requests.
                builder.body(Body::from(serde_json::to_vec(&resp).unwrap())).unwrap()
            },
            Err(ApiServerError::HttpStatusCode(status, msg)) => {
                builder.status(status).body(Body::from(msg)).unwrap()
            },
            Err(_) => {
                builder.status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::empty()).unwrap()
            },
        }
    }
}

/// Wrapper around a matchit router that allows different HTTP request types to
/// be matches
pub struct Router {
    /// The underlying router
    ///
    /// Holds a tuple of the handler and a boolean indicating whether
    /// wallet authentication (sk_root) signature is required for the request
    router: MatchRouter<(Box<dyn Handler>, AuthType)>,
    /// The auth middleware, authenticates a variety of requests
    auth_middleware: AuthMiddleware,
}

impl Router {
    /// Create a new router with no routes established
    pub fn new(admin_key: Option<SymmetricAuthKey>, state: State) -> Self {
        let router = MatchRouter::new();
        let auth_middleware = AuthMiddleware::new(admin_key, state);
        Self { router, auth_middleware }
    }

    /// Helper to build a routable path from a method and a concrete route
    ///
    /// The `matchit::Router` works only on URLs directly; so we prepend the
    /// operation type to the URL when creating the route
    ///
    /// Concretely, if POST is valid to /route then we route to /POST/route
    fn create_full_route(method: &Method, mut route: String) -> String {
        // Prepend a "/" if not already done
        if !route.starts_with('/') {
            route = String::from("/") + &route;
        }

        // Matchit is URL only, so we prepend the request type to match directly
        let method_str = method.to_string();
        format!("/{}{}", method_str, route)
    }

    /// Add a route to the router
    pub fn add_route<H: Handler + 'static>(
        &mut self,
        method: &Method,
        route: String,
        auth: AuthType,
        handler: H,
    ) {
        debug!("Attached handler to route {route} with method {method}");
        let full_route = Self::create_full_route(method, route);

        self.router
            .insert(full_route, (Box::new(handler), auth))
            .expect("error attaching handler to route");
    }

    /// Add an unauthenticated route
    pub fn add_unauthenticated_route<H: Handler + 'static>(
        &mut self,
        method: &Method,
        route: String,
        handler: H,
    ) {
        self.add_route(method, route, AuthType::None, handler);
    }

    /// Add a route with wallet authentication
    pub fn add_wallet_authenticated_route<H: Handler + 'static>(
        &mut self,
        method: &Method,
        route: String,
        handler: H,
    ) {
        self.add_route(method, route, AuthType::Wallet, handler);
    }

    /// Add a route with admin authentication
    pub fn add_admin_authenticated_route<H: Handler + 'static>(
        &mut self,
        method: &Method,
        route: String,
        handler: H,
    ) {
        if self.auth_middleware.admin_auth_enabled() {
            self.add_route(method, route, AuthType::Admin, handler);
        } else {
            warn!("Admin authentication is not enabled, skipping route {route}");
        }
    }

    /// Route a request to a handler
    #[instrument(skip_all, fields(
        http.status_code,
        http.method = %method,
        http.route = %route,
    ))]
    pub async fn handle_req(
        &self,
        method: Method,
        route: Uri,
        mut req: Request<Body>,
    ) -> Response<Body> {
        let path = route.path();
        let res = if method == Method::OPTIONS {
            // If the request is an options request, handle it directly
            self.handle_options_req(path)
        } else {
            // Get the full routable path
            let full_route = Self::create_full_route(&method, path.to_string());

            // Dispatch to handler
            if let Ok(matched_path) = self.router.at(&full_route) {
                let (handler, auth) = matched_path.value;
                let params = matched_path.params;

                // Clone the params to take ownership
                let mut params_map = HashMap::with_capacity(params.len());
                for (key, value) in params.iter() {
                    params_map.insert(key.to_string(), value.to_string());
                }

                // Parse query params
                let query_params = match parse_query_params(route.query().unwrap_or("")) {
                    Ok(params) => params,
                    Err(e) => {
                        return build_400_response(e.to_string());
                    },
                };

                // Auth check and handler
                if let Err(e) = self.check_auth(*auth, &params_map, &mut req).await {
                    return e.into();
                }

                handler.as_ref().handle(req, params_map, query_params).await
            } else {
                build_404_response(format!("Route {route} for method {method} not found"))
            }
        };

        tracing::Span::current().record("http.status_code", res.status().as_str());

        res
    }

    /// Handle an options request
    fn handle_options_req(&self, route: &str) -> Response<Body> {
        // Get the set of allowed methods for this route
        let allowed_methods = vec![Method::GET, Method::POST]
            .into_iter()
            .filter_map(|method: Method| {
                let full_route = Self::create_full_route(&method, route.to_owned());
                self.router.at(&full_route).ok()?;
                Some(method)
            })
            // All routes allow OPTIONS
            .chain(iter::once(Method::OPTIONS))
            .collect_vec();

        // Combine the allowed methods into a comma separated string
        let allowed_methods_str = allowed_methods.iter().map(|method| method.as_str()).join(",");

        Response::builder()
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Headers", "*")
            .header("Access-Control-Allow-Methods", allowed_methods_str)
            .header("Access-Control-Allow-Credentials", "true")
            .header("Access-Control-Max-Age", PREFLIGHT_CACHE_TIME)
            .body(Body::from(""))
            .unwrap()
    }

    /// Validate a signature of the request's body by sk_root of the wallet
    async fn check_auth(
        &self,
        auth_type: AuthType,
        url_params: &HashMap<String, String>,
        req: &mut Request<Body>,
    ) -> Result<(), ApiServerError> {
        if auth_type == AuthType::None {
            return Ok(());
        }

        // Serialize the request then authenticate it
        let req_body =
            to_bytes(req.body_mut()).await.map_err(|err| bad_request(err.to_string()))?;

        match auth_type {
            AuthType::Wallet => {
                // Parse the wallet ID from the URL params
                let wallet_id = parse_wallet_id_from_params(url_params)?;
                self.auth_middleware
                    .authenticate_wallet_request(wallet_id, req.headers(), &req_body)
                    .await?;
            },
            AuthType::Admin => {
                self.auth_middleware.authenticate_admin_request(req.headers(), &req_body).await?;
            },
            AuthType::None => unreachable!(),
        }

        *req.body_mut() = Body::from(req_body);
        Ok(())
    }
}
