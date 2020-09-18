//! Experimental synchronous implementation, using `genio` `Read`/`Write` traits,
//! mostly for no_std environments.

mod client;
pub use client::client_side;
mod server;
pub use server::server_side;
mod util;
