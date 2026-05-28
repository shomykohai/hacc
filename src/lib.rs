#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod common;
mod error;
mod macros;
mod preloader;
pub mod traits;
pub use common::*;
pub use error::{Error, Result};
pub use preloader::Preloader;
pub use traits::TryRead;
#[cfg(feature = "alloc")]
pub use traits::TryWrite;
pub use zerocopy::{IntoBytes, TryFromBytes};
