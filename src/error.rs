use thiserror::Error as TError;

pub use crate::bootctrl::BootControlError;
pub use crate::common::gfh::GfhError;
pub use crate::da::DaError;
pub use crate::preloader::PreloaderError;
pub use crate::{ImageError, RpmbInfoError, SecCfgError};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(TError, Debug)]
pub enum Error {
    #[error("Image parsing error: {0:?}")]
    Image(#[from] ImageError),

    #[error("Seccfg parsing error: {0:?}")]
    SecCfg(#[from] SecCfgError),

    #[error("RPMB info parsing error: {0:?}")]
    Rpmb(#[from] RpmbInfoError),

    #[error("GFH parsing error: {0:?}")]
    Gfh(#[from] GfhError),

    #[error("Preloader parsing error: {0:?}")]
    Preloader(#[from] PreloaderError),

    #[error("DA parsing error: {0:?}")]
    Da(#[from] DaError),

    #[error("Boot control parsing error: {0:?}")]
    BootControl(#[from] BootControlError),

    #[error("Zerocopy error")]
    Zerocopy,
}
