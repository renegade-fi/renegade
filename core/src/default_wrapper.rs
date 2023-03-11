//! Defines a container type that implements clone on any default capable type
//!
//! Replaces the cloned value with the underlying default, allowing a value to be
//! passed once to across thread boundaries and then cloned again as default
//!
//! This is particularly useful when passing parameters into async runtimes, they
//! may be `take`n at the executor level, and then passed as default via dispatch
//! methods. See the gossip server for an example

use std::{
    borrow::{Borrow, BorrowMut},
    fmt::{Debug, Display},
    mem,
};

/// The default wrapper structure, wraps a default capable value in a cell that may
/// be taken or cloned once.
pub struct DefaultWrapper<D: Default>(D);

impl<D: Default> From<D> for DefaultWrapper<D> {
    fn from(d: D) -> Self {
        Self(d)
    }
}

impl<D: Default> DefaultWrapper<D> {
    /// Wrap a value
    pub fn new(d: D) -> Self {
        Self(d)
    }

    /// Take the underlying value, replacing it with default
    pub fn take(&mut self) -> D {
        mem::take(self).0
    }
}

impl<D: Default> Default for DefaultWrapper<D> {
    fn default() -> Self {
        Self(D::default())
    }
}

impl<D: Default> Clone for DefaultWrapper<D> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl<D: Default> Borrow<D> for DefaultWrapper<D> {
    fn borrow(&self) -> &D {
        &self.0
    }
}

impl<D: Default> BorrowMut<D> for DefaultWrapper<D> {
    fn borrow_mut(&mut self) -> &mut D {
        &mut self.0
    }
}

impl<D: Debug + Default> Debug for DefaultWrapper<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<D: Display + Default> Display for DefaultWrapper<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
