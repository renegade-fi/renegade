//! Defines the server for the publicly facing API (both HTTP and websocket)
//! that the relayer exposes
pub mod error;
mod routes;
pub mod server;
pub mod worker;
