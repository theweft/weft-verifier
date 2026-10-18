// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! # weft-verifier
//!
//! The trusted core of [weft](https://theweft.org): a pure, deterministic state-transition
//! function that verifies signed documents and delegations and decides what a device should run
//! and how it should be configured.
//!
//! - **No I/O**: no network, files, clock, randomness or global state. The shell passes state,
//!   facts and raw input bytes in; the verifier returns the new state and decisions.
//! - **`no_std`** (`core` + `alloc`): the same code runs on Linux and microcontrollers.
//! - **Deny by default**: anything malformed, unsigned, unauthorized or out of date has no effect.
//! - **Order independent**: inputs are sorted by digest before processing.
//!
//! In classic terms this crate is weft's *reference monitor* / *policy decision point*; the
//! executor that performs [`Instruction`]s is the enforcement point.
//!
//! ```
//! use weft_verifier::{cbor::Limits, step, DeviceFacts, VerifierState};
//!
//! let facts = DeviceFacts { tenant: "acme".into(), ..Default::default() };
//! let (state, decisions) = step(&VerifierState::default(), &[], &facts, &[], &Limits::DEFAULT);
//! assert!(decisions.actions.is_empty());
//! assert_eq!(state, VerifierState::default());
//! ```
#![doc(html_logo_url = "https://theweft.org/brand/repos/weft-verifier.svg")]
#![doc(html_favicon_url = "https://theweft.org/favicon.svg")]
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod cbor;
pub mod cose;
pub mod crypto;
pub mod doc;
pub mod resolve;
pub mod rights;
pub mod state;
mod verifier;

pub use verifier::{
    Decisions, DeviceFacts, Instruction, Kind, MAX_CHAIN_DEPTH, MAX_RIGHTS_PER_KEY, Mark, Reason,
    Rejection, Slot, TrustAnchor, VerifierState, step,
};
