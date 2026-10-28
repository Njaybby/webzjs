// Copyright 2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

//! Trusted display + pre-sign validation for the dialog-spoofing fix.
//!
//! "Show only what you can prove, sign only what you showed."
//!
//! - [`pczt_describe`] (Layer A) recovers a [`PcztSummary`] **from the PCZT
//!   itself** + the user's UFVK, binding each displayed output to the note
//!   commitment that will actually be signed.
//! - [`pczt_validate`] (Layer B) refuses anything that doesn't balance, spends
//!   foreign inputs, or carries an unprovable output.
//!
//! See `Architecture/Snap Issue Resolution Plan - Dialog Spoofing & Key Derivation.md`
//! §1.4–1.5.

use crate::error::Error;
use crate::UnifiedFullViewingKey;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

use orchard::keys::{FullViewingKey as OrchardFvk, Scope};
use pczt::roles::verifier::Verifier;
use webzjs_common::{pool, MigrationSummary, Network, Pczt, PcztOutputSummary, PcztSummary};
use zcash_keys::address::UnifiedAddress;
use zcash_keys::encoding::AddressCodec;
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::keys::AccountPubKey;
use zcash_transparent::pczt::Bip32Derivation;
use zip32::AccountId;

/// Recover a human-verifiable summary of what a PCZT does.
///
/// The Snap renders THIS, never the caller-supplied `signDetails`.
///
/// # Arguments
/// * `network` - "main" or "test"
/// * `pczt` - the PCZT the dApp wants signed
/// * `ufvk` - the signer's Unified Full Viewing Key (for OVK/IVK recovery)
///
/// # Returns
/// A JSON [`PcztSummary`] (`{ network, outputs, total_in, total_out, fee }`).
#[wasm_bindgen]
pub fn pczt_describe(
    network: &str,
    pczt: &Pczt,
    ufvk: &UnifiedFullViewingKey,
) -> Result<JsValue, Error> {
    let summary = pczt_describe_inner(
        Network::from_str(network)?,
        pczt.clone().into(),
        ufvk.as_inner(),
    )?;
    serde_wasm_bindgen::to_value(&summary).map_err(|e| Error::PcztDescribe(e.to_string()))
}

/// Validate that a PCZT is safe to sign with this user's key.
///
/// Returns `Ok(())` only if every spend is the user's, value balances, and the
/// fee is sane. Any failure is a hard reject — this is what kills blind signing.
#[wasm_bindgen]
pub fn pczt_validate(
    network: &str,
    pczt: &Pczt,
    ufvk: &UnifiedFullViewingKey,
) -> Result<(), Error> {
    pczt_validate_inner(
        Network::from_str(network)?,
        pczt.clone().into(),
        ufvk.as_inner(),
    )
}

// ---------------------------------------------------------------------------
// Inner entry points: plain Rust (no wasm), so they can be unit-tested against
// crafted spoof PCZTs without a browser. See tests/spoof_pczt.rs.
// ---------------------------------------------------------------------------

/// ZIP-317 marginal fee per logical action, in zatoshis.
const MARGINAL_FEE: u64 = 5_000;
/// ZIP-317 grace: the conventional fee covers at least this many logical actions.
const GRACE_ACTIONS: u64 = 2;
/// Defense-in-depth ceiling: a fee more than this multiple of the ZIP-317
/// conventional minimum is treated as an attempt to drain funds via the fee and
/// is rejected even though ZIP-317 itself sets no upper bound.
const FEE_CEILING_MULTIPLE: u64 = 1_000;

/// The accumulated result of walking a PCZT's bundles. [`pczt_describe_inner`]
/// returns `summary`; [`pczt_validate_inner`] enforces the boolean invariants
/// plus value balance and the ZIP-317 fee band.
struct Analysis {
    summary: PcztSummary,
    /// A real (non-dummy) input was found that is not spendable under `ufvk`.
    foreign_input: bool,
    /// A real input or output had its `value` redacted, so the transaction
    /// cannot be balance-checked (the safe verdict is to refuse).
    value_missing: bool,
    /// A declared value disagreed with its value commitment (`cv` / `cv_net`),
    /// i.e. the cleartext numbers were tampered relative to what is signed.
    cv_mismatch: bool,
    /// ZIP-317 logical action count, for the conventional-fee floor.
    logical_actions: u64,
}

/// Native core of [`pczt_describe`].
///
/// Walks the Orchard / Sapling / Transparent bundles with the [`Verifier`] role
/// (mirrors `pczt_sign.rs`) and, for every output, recomputes the note
/// commitment from the cleartext `(recipient, value, rseed)` carried in the
/// PCZT and checks it against the `cmx` / `cmu` that will be signed. That bind
/// is what ties the displayed numbers to the exact bytes signed — Layer A.3.
/// Transparent outputs are read directly from their `script_pubkey`.
pub fn pczt_describe_inner(
    network: Network,
    pczt: pczt::Pczt,
    ufvk: &zcash_keys::keys::UnifiedFullViewingKey,
) -> Result<PcztSummary, Error> {
    Ok(analyze(network, pczt, ufvk)?.summary)
}

/// Native core of [`pczt_validate`].
///
/// Layer B — "kill blind signing". Refuses the PCZT unless:
///   - every real spend is under this `ufvk` (no co-signing foreign inputs);
///   - every displayed output is commitment-bound (`verified`) — an unprovable
///     output is refused rather than shown as if attested;
///   - no declared value contradicts its value commitment;
///   - value balances (`total_in >= total_out`, no redacted values); and
///   - the fee sits within the ZIP-317 band (>= conventional minimum, and not
///     absurdly high).
///
/// Note: comparing against the dApp-supplied `signDetails` is the Snap glue
/// layer's job (it diffs these parsed values against the claim and rejects on
/// mismatch); this function attests to what the PCZT *itself* says.
pub fn pczt_validate_inner(
    network: Network,
    pczt: pczt::Pczt,
    ufvk: &zcash_keys::keys::UnifiedFullViewingKey,
) -> Result<(), Error> {
    let a = analyze(network, pczt, ufvk)?;

    if a.foreign_input {
        return Err(Error::PcztValidate(
            "PCZT spends an input that is not under this key".into(),
        ));
    }
    if a.value_missing {
        return Err(Error::PcztValidate(
            "PCZT has redacted input/output values; cannot verify the balance".into(),
        ));
    }
    if a.cv_mismatch {
        return Err(Error::PcztValidate(
            "a declared value does not match its value commitment".into(),
        ));
    }
    if let Some(unprovable) = a.summary.outputs.iter().find(|o| !o.verified) {
        return Err(Error::PcztValidate(format!(
            "refusing: {} output is not commitment-bound (unprovable)",
            unprovable.pool
        )));
    }

    let total_in = a.summary.total_in;
    let total_out = a.summary.total_out;
    if total_out > total_in {
        return Err(Error::PcztValidate(format!(
            "value does not balance: outputs {total_out} exceed inputs {total_in}"
        )));
    }
    let fee = total_in - total_out;

    let min_fee = MARGINAL_FEE.saturating_mul(GRACE_ACTIONS.max(a.logical_actions));
    if fee < min_fee {
        return Err(Error::PcztValidate(format!(
            "fee {fee} is below the ZIP-317 conventional minimum {min_fee}"
        )));
    }
    let max_fee = min_fee.saturating_mul(FEE_CEILING_MULTIPLE);
    if fee > max_fee {
        return Err(Error::PcztValidate(format!(
            "fee {fee} is implausibly high (> {max_fee}); refusing to sign"
        )));
    }

    Ok(())
}

/// Encode an Orchard receiver as a Unified Address string for display.
fn encode_orchard(network: &Network, addr: &orchard::Address) -> Option<String> {
    UnifiedAddress::from_receivers(Some(*addr), None, None).map(|ua| ua.encode(network))
}

/// Encode a Sapling receiver as a Unified Address string for display.
fn encode_sapling(network: &Network, addr: &sapling::PaymentAddress) -> Option<String> {
    UnifiedAddress::from_receivers(None, Some(*addr), None).map(|ua| ua.encode(network))
}

/// True iff this Orchard spend is recoverable under `ofvk`.
///
/// Attribution is made **only** via the nullifier bind: [`verify_nullifier`]
/// reconstructs the full note from the spend's `(recipient, value, rho, rseed)`
/// and checks both that `ofvk` scopes the recipient *and* that the note's
/// nullifier matches the one published in the action. That cryptographically
/// ties the exact note to our `nk`.
///
/// We deliberately do **not** fall back to comparing the spend's `fvk` field
/// against `ofvk`. That field is attacker-suppliable: a malicious PCZT can
/// "plant" the victim's FVK bytes onto a foreign note (with an intact but
/// foreign recipient, or with the recipient redacted), which a byte-comparison
/// fallback would then mis-attribute to the victim — defeating the
/// foreign-input check that is the core invariant of [`pczt_validate_inner`].
/// See `SECURITY_REPORT.md` Finding 1. A genuinely redacted spend cannot be
/// proven or signed by us anyway, and its missing `value` independently trips
/// the `value_missing` reject, so dropping the fallback loses no legitimate
/// case. Without an Orchard FVK we cannot attribute the spend at all.
///
/// [`verify_nullifier`]: orchard::pczt::Spend::verify_nullifier
fn orchard_spend_is_ours(spend: &orchard::pczt::Spend, ofvk: Option<&OrchardFvk>) -> bool {
    let Some(ofvk) = ofvk else { return false };
    spend.verify_nullifier(Some(ofvk)).is_ok()
}

/// Walk an Orchard-shaped bundle — either the Orchard pool or the NU6.3 Ironwood
/// pool, which reuses the identical action/key/receiver shape — accumulating
/// value, attribution, tampering flags, and one display row per real output into
/// the shared accumulators. Returns this bundle's ZIP-317 logical-action count.
///
/// Ironwood is deliberately walked by the SAME code as Orchard: the whole point
/// of the spoofing fix is that display and gate cannot diverge, and giving the
/// two pools separate walks would reintroduce exactly that risk. `pool` is the
/// only per-pool input, and it only tags the output row.
#[allow(clippy::too_many_arguments)]
fn analyze_orchard_like_bundle(
    bundle: &orchard::pczt::Bundle,
    pool: &str,
    network: &Network,
    ofvk: Option<&OrchardFvk>,
    outputs: &mut Vec<PcztOutputSummary>,
    total_in: &mut u64,
    total_out: &mut u64,
    foreign_input: &mut bool,
    value_missing: &mut bool,
    cv_mismatch: &mut bool,
) -> u64 {
    // ZIP-317 logical actions, excluding fully-dummy padding the builder inserts
    // (both spend and output value 0). Such padding is invisible in the display
    // yet would otherwise inflate the fee band — see SECURITY_REPORT.md Finding 2.
    // A real spend OR a real output makes an action count; counting only the spend
    // would wrongly drop output-only actions (dummy spend + real output).
    let n_actions = bundle
        .actions()
        .iter()
        .filter(|action| {
            action.spend().value().map(|v| v.inner()) != Some(0)
                || action.output().value().map(|v| v.inner()) != Some(0)
        })
        .count() as u64;

    for action in bundle.actions() {
        let spend = action.spend();
        let output = action.output();

        // --- spend side ---
        match spend.value().map(|v| v.inner()) {
            // Dummy padding spend; contributes nothing.
            Some(0) => {}
            Some(v) => {
                if orchard_spend_is_ours(spend, ofvk) {
                    *total_in += v;
                } else {
                    *foreign_input = true;
                }
            }
            // Real spend with a redacted value: cannot balance or attribute.
            None => {
                *value_missing = true;
                if !orchard_spend_is_ours(spend, ofvk) {
                    *foreign_input = true;
                }
            }
        }

        // The value commitment binds the declared values to what is signed; a
        // definite mismatch is tampering. Missing `rcv` or values just means we
        // lean on the nullifier/cmx binds instead.
        if let Err(orchard::pczt::VerifyError::InvalidValueCommitment) = action.verify_cv_net() {
            *cv_mismatch = true;
        }

        // --- output side ---
        match output.value().map(|v| v.inner()) {
            // Dummy padding output; not shown.
            Some(0) => {}
            // Redacted value: trip `value_missing` (so `pczt_validate` rejects) but
            // do NOT push a 0-ZEC entry into the display — that would render as a
            // misleading "0.00000000 ZEC" output before the reject
            // (SECURITY_REPORT.md Finding 4).
            None => {
                *value_missing = true;
            }
            Some(value) => {
                // Bind the displayed (recipient, value) to the signed cmx.
                let verified = output.verify_note_commitment(spend).is_ok();
                let recipient = output
                    .recipient()
                    .as_ref()
                    .and_then(|a| encode_orchard(network, a));
                let scope = output
                    .recipient()
                    .as_ref()
                    .and_then(|a| ofvk.and_then(|k| k.scope_for_address(a)));
                let is_change = scope == Some(Scope::Internal);
                let is_ours = scope.is_some();
                *total_out += value;
                outputs.push(PcztOutputSummary {
                    pool: pool.into(),
                    recipient,
                    value,
                    memo: None,
                    is_change,
                    is_ours,
                    verified,
                });
            }
        }
    }

    n_actions
}

/// The BIP-44 account this Snap derives keys for (Zcash Snap convention: account 0).
const SNAP_ACCOUNT: u32 = 0;

/// True iff some key that can authorize a transparent coin re-derives from our
/// transparent account FVK at its declared BIP-32 path **and** hashes to the exact
/// address on the coin (`addr`).
///
/// This is the transparent analogue of the shielded nullifier check, and it is
/// **viewing-key-only** — it needs no seed. For each `(pubkey, derivation)` the PCZT
/// records, we re-derive the pubkey from our account FVK at the claimed path; the
/// bind is "our FVK genuinely produces this pubkey, and the coin pays to its
/// address." The `seed_fingerprint` recorded alongside the path is an *unverified
/// hint* and is deliberately ignored — a malicious dApp can put anything there, so
/// it must never be the basis for attribution.
///
/// Returns `false` when the UFVK carries no transparent component (`tfvk == None`):
/// that key genuinely cannot see this pool, so the safe verdict is "not ours".
fn transparent_addr_is_ours(
    network: &Network,
    tfvk: Option<&AccountPubKey>,
    addr: &TransparentAddress,
    bip32_derivation: &BTreeMap<[u8; 33], Bip32Derivation>,
) -> bool {
    let Some(tfvk) = tfvk else { return false };
    let Ok(account) = AccountId::try_from(SNAP_ACCOUNT) else {
        return false;
    };
    bip32_derivation.iter().any(|(claimed_pk, deriv)| {
        match tfvk.derive_pubkey_at_bip32_path(network, account, deriv.derivation_path()) {
            Ok(pk) => &pk.serialize() == claimed_pk && TransparentAddress::from_pubkey(&pk) == *addr,
            Err(_) => false,
        }
    })
}

/// Recognize a NU6.3 Path-A migration (ZIP 318 "Migrate Immediately") from the
/// per-output summary. Returns `Some` iff the PCZT creates any Ironwood output —
/// i.e. it moves value into the Ironwood pool. In the current Path-A-only world
/// (no Ironwood scanning/spending yet), an Ironwood output can only be a
/// migration, so this recognition is exact; when Ironwood-to-Ironwood payments
/// later exist this heuristic will need the caller's intent to disambiguate.
///
/// The returned [`MigrationSummary`] drives the consent dialog; it does **not**
/// gate signing — [`pczt_validate_inner`] already enforces the hard safety
/// invariants (spends are ours, value balances / turnstile identity holds, every
/// output is commitment-bound, fee is sane) for migrations as for any PCZT.
fn detect_migration(outputs: &[PcztOutputSummary]) -> Option<MigrationSummary> {
    let ironwood: Vec<&PcztOutputSummary> =
        outputs.iter().filter(|o| o.pool == pool::IRONWOOD).collect();
    if ironwood.is_empty() {
        return None;
    }
    let amount = ironwood.iter().map(|o| o.value).sum();
    // Self-migration iff every Ironwood output pays one of our own addresses.
    let to_self = ironwood.iter().all(|o| o.is_ours);
    // Clean Path A: the whole balance into a single Ironwood note, with any other
    // output being change back to us — no third-party payments riding along.
    let others_all_ours = outputs
        .iter()
        .filter(|o| o.pool != pool::IRONWOOD)
        .all(|o| o.is_ours);
    let is_clean_path_a = ironwood.len() == 1 && others_all_ours;
    Some(MigrationSummary {
        amount,
        to_self,
        is_clean_path_a,
    })
}

/// Walk the PCZT once and accumulate the trusted-display summary plus the
/// invariants [`pczt_validate_inner`] enforces.
fn analyze(
    network: Network,
    pczt: pczt::Pczt,
    ufvk: &zcash_keys::keys::UnifiedFullViewingKey,
) -> Result<Analysis, Error> {
    let ofvk = ufvk.orchard();
    let sdfvk = ufvk.sapling();
    let sfvk = sdfvk.map(|dfvk| dfvk.fvk());
    let tfvk = ufvk.transparent();

    let mut outputs: Vec<PcztOutputSummary> = Vec::new();
    let mut total_in: u64 = 0;
    let mut total_out: u64 = 0;
    let mut foreign_input = false;
    let mut value_missing = false;
    let mut cv_mismatch = false;
    let mut n_orchard_actions: u64 = 0;
    let mut n_ironwood_actions: u64 = 0;
    let mut n_sapling_actions: u64 = 0;
    let mut n_tin: u64 = 0;
    let mut n_tout: u64 = 0;

    // Each `with_*` closure runs to completion before the next, so the mutable
    // borrows of the accumulators above never overlap.
    let verifier = Verifier::new(pczt);

    let verifier = verifier
        .with_orchard::<Infallible, _>(|bundle| {
            n_orchard_actions = analyze_orchard_like_bundle(
                bundle,
                pool::ORCHARD,
                &network,
                ofvk,
                &mut outputs,
                &mut total_in,
                &mut total_out,
                &mut foreign_input,
                &mut value_missing,
                &mut cv_mismatch,
            );
            Ok(())
        })
        .map_err(|e| Error::PcztDescribe(format!("Invalid Orchard bundle: {e:?}")))?;

    // NU6.3 / Ironwood. A v6 PCZT carries an `ironwood` bundle after the Orchard
    // one. Ironwood reuses the Orchard action/key/receiver shape (same
    // `orchard::pczt::Bundle`, same FVK/nullifier, same UA Orchard receiver), so
    // it is walked by the *same* code as Orchard — display and gate cannot diverge
    // between the two pools. The only differences are internal to the parsed
    // bundle (v3 note plaintext, Ironwood note-encryption domain), which
    // `with_ironwood`/`verify_note_commitment` already account for. Rows are tagged
    // `pool = "ironwood"`. Was previously a hard "reject any Ironwood bundle" guard
    // (there was no `.with_ironwood()` lens); now that upstream ships the lens, we
    // describe and attribute it properly.
    let verifier = verifier
        .with_ironwood::<Infallible, _>(|bundle| {
            n_ironwood_actions = analyze_orchard_like_bundle(
                bundle,
                pool::IRONWOOD,
                &network,
                ofvk,
                &mut outputs,
                &mut total_in,
                &mut total_out,
                &mut foreign_input,
                &mut value_missing,
                &mut cv_mismatch,
            );
            Ok(())
        })
        .map_err(|e| Error::PcztDescribe(format!("Invalid Ironwood bundle: {e:?}")))?;

    let verifier = verifier
        .with_sapling::<Infallible, _>(|bundle| {
            n_sapling_actions = bundle.spends().len().max(bundle.outputs().len()) as u64;

            for spend in bundle.spends() {
                if let Err(sapling::pczt::VerifyError::InvalidValueCommitment) = spend.verify_cv() {
                    cv_mismatch = true;
                }
                match spend.value().map(|v| v.inner()) {
                    Some(0) => {}
                    Some(v) => {
                        if sfvk.map(|fvk| spend.verify_nullifier(Some(fvk)).is_ok()) == Some(true) {
                            total_in += v;
                        } else {
                            foreign_input = true;
                        }
                    }
                    None => {
                        value_missing = true;
                        foreign_input = true;
                    }
                }
            }

            for output in bundle.outputs() {
                if let Err(sapling::pczt::VerifyError::InvalidValueCommitment) = output.verify_cv() {
                    cv_mismatch = true;
                }
                match output.value().map(|v| v.inner()) {
                    Some(0) => {}
                    // Redacted value: reject via `value_missing`, don't display a
                    // 0-ZEC entry (SECURITY_REPORT.md Finding 4).
                    None => {
                        value_missing = true;
                    }
                    Some(value) => {
                        let verified = output.verify_note_commitment().is_ok();
                        let addr = output.recipient();
                        let recipient = addr.as_ref().and_then(|a| encode_sapling(&network, a));
                        // Change = the note pays back to one of our own internal (change)
                        // addresses. NB: `DiversifiableFullViewingKey::decrypt_diversifier`
                        // is unreliable for the internal scope in sapling-crypto 0.6 (its
                        // internal branch checks the external key), so we reconstruct the
                        // change address for the output's own diversifier and compare.
                        let is_change = addr
                            .as_ref()
                            .and_then(|a| {
                                sdfvk.map(|dfvk| {
                                    dfvk.diversified_change_address(*a.diversifier()).as_ref()
                                        == Some(a)
                                })
                            })
                            .unwrap_or(false);
                        total_out += value;
                        outputs.push(PcztOutputSummary {
                            pool: pool::SAPLING.into(),
                            recipient,
                            value,
                            memo: None,
                            is_change,
                            // We only positively detect the internal (change) scope for
                            // Sapling here; treat that as the extent of "ours". A
                            // Path-A migration carries no Sapling outputs, so this only
                            // affects the conservative `is_clean_path_a` check.
                            is_ours: is_change,
                            verified,
                        });
                    }
                }
            }
            Ok(())
        })
        .map_err(|e| Error::PcztDescribe(format!("Invalid Sapling bundle: {e:?}")))?;

    let verifier = verifier
        .with_transparent::<Infallible, _>(|bundle| {
            n_tin = bundle.inputs().len() as u64;
            n_tout = bundle.outputs().len() as u64;

            // Attribute each transparent spend to our key, exactly as the shielded
            // pools attribute via nullifiers. The address being spent is recovered
            // from the prevout `script_pubkey` (a `FromChain` script), then bound to
            // a pubkey our account FVK derives. A spend we cannot attribute is
            // foreign and makes the PCZT unsafe to co-sign.
            for input in bundle.inputs() {
                let value = u64::from(*input.value());
                total_in += value;
                let ours = TransparentAddress::from_script_from_chain(input.script_pubkey())
                    .map(|addr| transparent_addr_is_ours(&network, tfvk, &addr, input.bip32_derivation()))
                    .unwrap_or(false);
                if !ours {
                    foreign_input = true;
                }
            }

            for output in bundle.outputs() {
                let value = u64::from(*output.value());
                // The script_pubkey is part of the signed transaction, so the
                // recovered address is bound directly — `verified = true`.
                let addr = TransparentAddress::from_script_pubkey(output.script_pubkey());
                let recipient = addr.map(|addr| addr.encode(&network));
                // Change = the coin pays back to one of our own transparent keys.
                let is_change = addr
                    .map(|addr| transparent_addr_is_ours(&network, tfvk, &addr, output.bip32_derivation()))
                    .unwrap_or(false);
                total_out += value;
                outputs.push(PcztOutputSummary {
                    pool: pool::TRANSPARENT.into(),
                    recipient,
                    value,
                    memo: None,
                    is_change,
                    // `is_change` here already means "pays one of our transparent
                    // keys", i.e. ours.
                    is_ours: is_change,
                    verified: true,
                });
            }
            Ok(())
        })
        .map_err(|e| Error::PcztDescribe(format!("Invalid Transparent bundle: {e:?}")))?;

    let _ = verifier.finish();

    let logical_actions =
        n_tin.max(n_tout) + n_sapling_actions + n_orchard_actions + n_ironwood_actions;

    let migration = detect_migration(&outputs);
    let summary = PcztSummary {
        network: match network {
            Network::MainNetwork => "main".into(),
            Network::TestNetwork => "test".into(),
            Network::Regtest => "regtest".into(),
        },
        outputs,
        total_in,
        total_out,
        fee: total_in.saturating_sub(total_out),
        migration,
    };

    Ok(Analysis {
        summary,
        foreign_input,
        value_missing,
        cv_mismatch,
        logical_actions,
    })
}
