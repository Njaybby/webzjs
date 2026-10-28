//! Reads and writes a sealed auction room needs on top of the stock wallet.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zcash_client_backend::data_api::{Account, WalletRead};
use zcash_client_backend::proto::service::BlockId;
use zcash_client_backend::wallet::{Note, OvkPolicy};
use zcash_client_backend::zip321::TransactionRequest;
use std::collections::HashMap;
use zcash_client_backend::decrypt_transaction;
use zcash_client_backend::proto::service::TxFilter;
use zcash_keys::encoding::encode_payment_address;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkConstants, Parameters};
use zcash_protocol::memo::Memo;
use zip32::{DiversifierIndex, Scope};

use crate::bindgen::proposal::Proposal;
use crate::bindgen::wallet::WebWallet;
use crate::error::Error;
use crate::wallet::usk_from_seed_str;
use wasm_thread as thread;

/// One shielded output an account received, as a room member sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomNote {
    pub txid: String,
    /// Action index within the transaction, which orders two notes from the same transaction.
    pub index: u16,
    pub pool: String,
    /// Zatoshis.
    pub value: u64,
    /// The memo as text, or None when it is empty or not text.
    pub memo: Option<String>,
    pub height: Option<u32>,
    /// The external diversifier index the note was paid to, as a decimal string, or None for change and for notes this key cannot place.
    pub address_index: Option<String>,
    pub change: bool,
}

#[wasm_bindgen]
impl WebWallet {
    /// The account's Sapling address for paddle `index`.
    /// The in-memory store does not track Ironwood notes, so rooms receive in the Sapling pool.
    /// Not every Sapling diversifier is valid, so paddle `n` takes the first valid index from `n << 16`, and `room_notes` maps it back with `>> 16`.
    pub async fn address_at(&self, account_id: u32, index: u64) -> Result<String, Error> {
        let db = self.inner.db.read().await;
        let account = db
            .get_account(account_id.into())?
            .ok_or(Error::AccountNotFound(account_id))?;
        let dfvk = account
            .ufvk()
            .and_then(|k| k.sapling())
            .ok_or(Error::AccountNotFound(account_id))?;
        let start = DiversifierIndex::from(index << 16);
        let (_, addr) = dfvk
            .find_address(start)
            .ok_or_else(|| Error::Sync("no valid Sapling diversifier for this paddle".into()))?;
        Ok(encode_payment_address(
            self.inner.network.network_type().hrp_sapling_payment_address(),
            &addr,
        ))
    }

    /// The account's unified full viewing key, encoded for this network, so room members can import the room as a view-only account.
    pub async fn account_ufvk(&self, account_id: u32) -> Result<String, Error> {
        let db = self.inner.db.read().await;
        let account = db
            .get_account(account_id.into())?
            .ok_or(Error::AccountNotFound(account_id))?;
        let ufvk = account.ufvk().ok_or(Error::AccountNotFound(account_id))?;
        Ok(ufvk.encode(&self.inner.network))
    }

    /// Every note the account received, with the paddle it was paid to and its memo.
    /// The compact scan carries neither, so each transaction is fetched whole and decrypted here.
    pub async fn room_notes(&self, account_id: u32) -> Result<JsValue, Error> {
        let (ufvk, notes) = {
            let db = self.inner.db.read().await;
            let account = db
                .get_account(account_id.into())?
                .ok_or(Error::AccountNotFound(account_id))?;
            let ufvk = account.ufvk().cloned().ok_or(Error::AccountNotFound(account_id))?;
            let notes: Vec<_> = db
                .received_notes()
                .iter()
                .filter(|n| n.account_id() == account_id.into())
                .map(|n| {
                    let pool = match n.note() {
                        Note::Sapling(_) => "sapling",
                        Note::Orchard { pool: orchard::ValuePool::Orchard, .. } => "orchard",
                        Note::Orchard { pool: orchard::ValuePool::Ironwood, .. } => "ironwood",
                    };
                    let txid = n.txid();
                    (
                        txid,
                        n.note_id().output_index(),
                        pool,
                        n.note().value().into_u64(),
                        db.tx_table().get(&txid).and_then(|t| t.mined_height()),
                    )
                })
                .collect();
            (ufvk, notes)
        };
        let network = self.inner.network;
        let ufvks = HashMap::from([(0u32, ufvk.clone())]);
        let mut client = self.client();
        let mut decrypted: HashMap<TxId, Vec<(usize, Option<String>, Option<String>)>> = HashMap::new();
        let mut out = Vec::new();
        for (txid, index, pool, value, height) in notes {
            if pool == "sapling" && !decrypted.contains_key(&txid) {
                let raw = client
                    .get_transaction(TxFilter { block: None, index: 0, hash: txid.as_ref().to_vec() })
                    .await?
                    .into_inner();
                let h = height.unwrap_or_else(|| BlockHeight::from_u32(raw.height as u32));
                let tx = Transaction::read(&raw.data[..], BranchId::for_height(&network, h))?;
                let d = decrypt_transaction(&network, Some(h), None, &tx, &ufvks);
                let dfvk = ufvk.sapling();
                let rows = d
                    .sapling_outputs()
                    .iter()
                    .map(|o| {
                        let memo = match Memo::try_from(o.memo().clone()) {
                            Ok(Memo::Text(t)) if !t.is_empty() => Some(t.to_string()),
                            _ => None,
                        };
                        let paddle = match dfvk.and_then(|k| k.decrypt_diversifier(&o.note().recipient())) {
                            Some((j, Scope::External)) => {
                                let mut b = [0u8; 16];
                                b[..11].copy_from_slice(j.as_bytes());
                                Some((u128::from_le_bytes(b) >> 16).to_string())
                            }
                            _ => None,
                        };
                        (o.index(), memo, paddle)
                    })
                    .collect();
                decrypted.insert(txid, rows);
            }
            let found = decrypted
                .get(&txid)
                .and_then(|rows| rows.iter().find(|r| r.0 == index as usize));
            let (memo, address_index) = found.map(|r| (r.1.clone(), r.2.clone())).unwrap_or((None, None));
            out.push(RoomNote {
                txid: txid.to_string(),
                index,
                pool: pool.to_string(),
                value,
                memo,
                height: height.map(u32::from),
                change: address_index.is_none(),
                address_index,
            });
        }
        Ok(serde_wasm_bindgen::to_value(&out)?)
    }

    /// The block's header time in seconds, from the light server.
    pub async fn block_time(&self, height: u64) -> Result<u32, Error> {
        let block = self
            .client()
            .get_block(BlockId { height, hash: vec![] })
            .await?
            .into_inner();
        Ok(block.time)
    }

    /// Proposes a transaction paying a ZIP 321 request, with every output and memo it carries.
    pub async fn propose_request(&self, account_id: u32, uri: String) -> Result<Proposal, Error> {
        let request = TransactionRequest::from_uri(&uri)
            .map_err(|e| Error::Generic(format!("invalid payment request: {e:?}")))?;
        let proposal = self.inner.propose_request(account_id.into(), request).await?;
        Ok(proposal.into())
    }

    /// Proves and signs a proposal with the outgoing viewing key discarded, so a holder of the account's full viewing key cannot read where the outputs went.
    /// Returns the transaction ids flattened, 32 bytes each.
    pub async fn create_proposed_transactions_private(
        &self,
        proposal: Proposal,
        seed_phrase: &str,
        account_hd_index: u32,
    ) -> Result<Vec<u8>, Error> {
        assert!(!thread::is_web_worker_thread());
        let (usk, _) = usk_from_seed_str(seed_phrase, account_hd_index, &self.inner.network)?;
        let db = self.inner.clone();
        let txids = thread::Builder::new()
            .name("create_private_transaction".to_string())
            .spawn_async(|| async move {
                db.create_proposed_transactions_with_ovk(proposal.into(), &usk, OvkPolicy::Discard)
                    .await
                    .map_err(|e| e.to_string())
            })
            .unwrap_throw()
            .join_async()
            .await
            .map_err(|e| Error::Generic(format!("transaction thread panicked: {e:?}")))?
            .map_err(Error::Generic)?;
        Ok(txids.iter().flat_map(|t| t.as_ref().clone()).collect())
    }
}
