use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Immutable, IntoBytes, TryFromBytes, KnownLayout,
)]
#[repr(C)]
pub enum LockState {
    Default = 1,
    MpDefault = 2,
    Unlock = 3,
    #[default]
    Lock = 4,
    Verified = 5,
    Custom = 6,
}
