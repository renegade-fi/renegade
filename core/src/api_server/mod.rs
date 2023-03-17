//! Defines the server for the publicly facing API (both HTTP and websocket)
//! that the relayer exposes
pub mod error;
mod http;
mod router;
mod websocket;
pub mod worker;
