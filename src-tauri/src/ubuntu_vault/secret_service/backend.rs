//! oo7-backed Secret Service glue (FEAT-005 "Provider-neutral client",
//! "Existing provider only", "Default/login collection").
//!
//! Production uses ONLY `oo7::dbus::Service::encrypted()` — an encrypted
//! D-Bus session with no plain-session fallback, no automatic backend
//! selection, and no file/portal backend. All oo7 errors are normalized to the
//! closed `ProviderFailure` vocabulary before anything else sees them.
//!
//! This module deliberately contains no classification logic: every rule
//! lives in the pure `state`/`rotation` modules so the security decisions are
//! exhaustively unit-testable without a session bus. The async methods here
//! are thin, bounded D-Bus calls; real-provider integration runs only in
//! Phase 7's isolated synthetic desktop account harness.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::ubuntu_vault::contracts::wrapper::ReleaseChannel;
use crate::ubuntu_vault::secret_service::state::ProbeOutcome;
use crate::ubuntu_vault::secret_service::ProviderFailure;
use crate::ubuntu_vault::{APPLICATION_ID, ITEM_LABEL, ITEM_PURPOSE, WRAPPER_FORMAT_VERSION};

/// Fixed Secret Service item attribute keys (identity-free vocabulary).
pub const ATTR_APPLICATION_ID: &str = "application-id";
pub const ATTR_RELEASE_CHANNEL: &str = "release-channel";
pub const ATTR_PURPOSE: &str = "purpose";
pub const ATTR_WRAPPER_FORMAT_VERSION: &str = "wrapper-format-version";

/// Fixed purpose value marking a clearly staged (rotation) temporary item.
/// The staged item is a temporary second keyring entry created only during a
/// verified rotation; at steady state exactly one active item exists.
pub const STAGED_ITEM_PURPOSE: &str = "vault-wrapper-staged";

/// Secret content type for raw 32-byte wrapping keys.
const SECRET_CONTENT_TYPE: &str = "application/octet-stream";

/// Identity-free item attributes for one release channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemAttributes {
    pub release_channel: ReleaseChannel,
    pub purpose: &'static str,
}

impl ItemAttributes {
    /// Active (steady-state) wrapping item attributes.
    pub fn active(release_channel: ReleaseChannel) -> Self {
        Self {
            release_channel,
            purpose: ITEM_PURPOSE,
        }
    }

    /// Staged (rotation) item attributes — clearly marked temporary.
    pub fn staged(release_channel: ReleaseChannel) -> Self {
        Self {
            release_channel,
            purpose: STAGED_ITEM_PURPOSE,
        }
    }

    /// The fixed attribute map stored on the Secret Service item. Contains no
    /// alias, username/UID, address, profile ID, mnemonic status, endpoint,
    /// network, or vault generation.
    pub fn to_map(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        map.insert(ATTR_APPLICATION_ID.to_string(), APPLICATION_ID.to_string());
        map.insert(
            ATTR_RELEASE_CHANNEL.to_string(),
            self.release_channel.as_str().to_string(),
        );
        map.insert(ATTR_PURPOSE.to_string(), self.purpose.to_string());
        map.insert(
            ATTR_WRAPPER_FORMAT_VERSION.to_string(),
            WRAPPER_FORMAT_VERSION.to_string(),
        );
        map
    }

    /// Whether an observed attribute map matches this fixed vocabulary
    /// (application id, channel, purpose, wrapper version exactly).
    pub fn matches(&self, observed: &BTreeMap<String, String>) -> bool {
        observed == &self.to_map()
    }
}

/// Opaque handle to a stored wrapping item. `item_index` is a deterministic
/// ordinal assigned by this process — never the D-Bus object path, which stays
/// internal to `Oo7Backend`. Attributes are included for cardinality logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredItem {
    pub item_index: u64,
    pub attributes: BTreeMap<String, String>,
}

impl StoredItem {
    /// Whether this item is the fixed active vocabulary entry.
    pub fn is_active(&self) -> bool {
        self.attributes.get(ATTR_PURPOSE).map(String::as_str) == Some(ITEM_PURPOSE)
    }

    /// Whether this item is the clearly staged rotation entry.
    pub fn is_staged(&self) -> bool {
        self.attributes.get(ATTR_PURPOSE).map(String::as_str) == Some(STAGED_ITEM_PURPOSE)
    }
}

/// Normalize an oo7 error into the closed provider failure vocabulary.
///
/// - `ServiceUnknown`/`NameHasNoOwner` → confirmed absence (fallback-eligible
///   only after OS setup/Retry guidance at the UI layer).
/// - Prompt dismissal → `PromptCancelled`; the 60-second prompt bound is
///   enforced by the caller (tokio timeout) and maps to `PromptTimedOut`.
/// - Missing default collection → absence of a usable default collection.
/// - Everything else → a safe transient/closed mapping. No raw detail escapes.
pub fn map_oo7_error(error: &oo7::dbus::Error) -> ProviderFailure {
    use oo7::dbus::ServiceError;
    match error {
        oo7::dbus::Error::Dismissed => ProviderFailure::PromptCancelled,
        oo7::dbus::Error::NotFound(_) => ProviderFailure::Absent,
        oo7::dbus::Error::Deleted => ProviderFailure::Deleted,
        oo7::dbus::Error::Service(ServiceError::IsLocked) => ProviderFailure::Locked,
        oo7::dbus::Error::Service(_) => ProviderFailure::TemporarilyUnavailable,
        // `oo7` re-exports `zbus` at `oo7::zbus`; the D-Bus name-ownership
        // errors are the only confirmed-absence signal from the wire.
        oo7::dbus::Error::Zbus(e) => match e {
            oo7::zbus::Error::FDO(fdo) => match &**fdo {
                oo7::zbus::fdo::Error::ServiceUnknown(_)
                | oo7::zbus::fdo::Error::NameHasNoOwner(_) => ProviderFailure::Absent,
                _ => ProviderFailure::TemporarilyUnavailable,
            },
            _ => ProviderFailure::TemporarilyUnavailable,
        },
        _ => ProviderFailure::Internal,
    }
}

/// Real Secret Service backend over `oo7::dbus::Service::encrypted()`.
///
/// The D-Bus connection and the default/login collection are opened once per
/// native process and reused; the shared collection is never locked,
/// reconfigured, or created by HushVoting.
pub struct Oo7Backend {
    collection: oo7::dbus::Collection<'static>,
    release_channel: ReleaseChannel,
    /// Internal mapping: process-assigned ordinal → live oo7 item. The D-Bus
    /// object path never leaves this struct.
    items: Vec<(u64, oo7::dbus::Item<'static>)>,
    next_index: u64,
}

impl Oo7Backend {
    /// Connect an encrypted session to the user's existing provider and open
    /// the default/login collection. No prompt is raised here (non-prompting
    /// connect + probe); an explicit user action precedes any later unlock.
    ///
    /// The `Service` handle itself is not retained: `Collection`/`Item` hold
    /// `Arc` references to the same `api::Service`, so the D-Bus connection
    /// stays alive for the process lifetime without an extra field.
    pub async fn connect(release_channel: ReleaseChannel) -> Result<Self, ProviderFailure> {
        let service = oo7::dbus::Service::encrypted()
            .await
            .map_err(|e| map_oo7_error(&e))?;
        let collection = service
            .default_collection()
            .await
            .map_err(|e| map_oo7_error(&e))?;
        Ok(Self {
            collection,
            release_channel,
            items: Vec::new(),
            next_index: 0,
        })
    }

    /// Non-prompting startup probe: reports the default collection's locked
    /// state (a property read — never raises an OS prompt).
    pub async fn probe(&self) -> Result<ProbeOutcome, ProviderFailure> {
        let locked = self
            .collection
            .is_locked()
            .await
            .map_err(|e| map_oo7_error(&e))?;
        Ok(if locked {
            ProbeOutcome::ConnectedLocked
        } else {
            ProbeOutcome::ConnectedUnlocked
        })
    }

    /// Explicit user-action unlock: raises the OS provider's normal prompt for
    /// the default collection. Bounded by `PROMPT_BOUND_SECS` at the caller.
    pub async fn unlock_default_collection(&self) -> Result<(), ProviderFailure> {
        self.collection
            .unlock()
            .await
            .map_err(|e| map_oo7_error(&e))
    }

    /// Search the default collection for items matching the fixed active or
    /// staged vocabulary for this release channel. Deterministic ordinal
    /// indexing; search order never selects a key.
    pub async fn search(
        &mut self,
        attributes: &ItemAttributes,
    ) -> Result<Vec<StoredItem>, ProviderFailure> {
        let map = attributes.to_map();
        let items = self
            .collection
            .search_items(&map)
            .await
            .map_err(|e| map_oo7_error(&e))?;
        self.items = items
            .into_iter()
            .map(|item| {
                let index = self.next_index;
                self.next_index += 1;
                (index, item)
            })
            .collect();
        let mut result = Vec::with_capacity(self.items.len());
        for (index, item) in &self.items {
            // Attribute reads are non-prompting property reads; a failure
            // (e.g. collection re-locked) maps to the closed vocabulary.
            let attrs: BTreeMap<String, String> = item
                .attributes()
                .await
                .map_err(|e| map_oo7_error(&e))?
                .into_iter()
                .collect();
            result.push(StoredItem {
                item_index: *index,
                attributes: attrs,
            });
        }
        Ok(result)
    }

    /// Read the wrapping key secret from an item into a zeroizing container.
    /// The key is held only for the bounded wrap/unwrap and cleared
    /// immediately afterward by the caller.
    pub async fn read_secret(
        &self,
        item: &StoredItem,
    ) -> Result<Zeroizing<Vec<u8>>, ProviderFailure> {
        let oo7_item = &self
            .items
            .iter()
            .find(|(index, _)| *index == item.item_index)
            .ok_or(ProviderFailure::Deleted)?
            .1;
        oo7_item.secret().await.map_err(|e| map_oo7_error(&e))
    }

    /// Create a wrapping item (active or staged) with the fixed identity-free
    /// attributes and the given raw key bytes. `replace` is always false: an
    /// existing matching item is never silently overwritten.
    pub async fn create_item(
        &mut self,
        attributes: &ItemAttributes,
        secret: &[u8],
    ) -> Result<StoredItem, ProviderFailure> {
        let map = attributes.to_map();
        let item = self
            .collection
            .create_item(ITEM_LABEL, &map, secret, false, SECRET_CONTENT_TYPE)
            .await
            .map_err(|e| map_oo7_error(&e))?;
        let index = self.next_index;
        self.next_index += 1;
        self.items.push((index, item));
        Ok(StoredItem {
            item_index: index,
            attributes: map,
        })
    }

    /// Delete a wrapping item (verified cleanup only — see `rotation`).
    pub async fn delete_item(&mut self, item: &StoredItem) -> Result<(), ProviderFailure> {
        let oo7_item = &self
            .items
            .iter()
            .find(|(index, _)| *index == item.item_index)
            .ok_or(ProviderFailure::Deleted)?
            .1;
        oo7_item.delete().await.map_err(|e| map_oo7_error(&e))?;
        self.items.retain(|(index, _)| *index != item.item_index);
        Ok(())
    }

    /// Verify search-absence of the fixed vocabulary after deletion (the
    /// removal/replacement paths require absence verification before success).
    pub async fn search_absent(
        &mut self,
        attributes: &ItemAttributes,
    ) -> Result<bool, ProviderFailure> {
        let found = self.search(attributes).await?;
        Ok(found.is_empty())
    }

    pub fn release_channel(&self) -> ReleaseChannel {
        self.release_channel
    }
}

impl crate::ubuntu_vault::lifecycle::removal::KeyringVaultOps for Oo7Backend {
    /// Delete active and staged wrapping items, then verify search absence.
    async fn delete_active_and_staged(&mut self) -> Result<bool, ProviderFailure> {
        for attributes in [
            ItemAttributes::active(self.release_channel()),
            ItemAttributes::staged(self.release_channel()),
        ] {
            let items = self.search(&attributes).await?;
            for item in items {
                self.delete_item(&item).await?;
            }
        }
        self.verify_absent().await
    }

    /// Verify that no active or staged wrapping item remains.
    async fn verify_absent(&mut self) -> Result<bool, ProviderFailure> {
        let active = ItemAttributes::active(self.release_channel());
        let staged = ItemAttributes::staged(self.release_channel());
        Ok(self.search_absent(&active).await? && self.search_absent(&staged).await?)
    }
}

/// In-memory provider double for deterministic tests. It stores raw key bytes
/// per attribute-set and records operations so rotation/removal logic can be
/// verified without any D-Bus access (and never touches a developer keyring).
#[cfg(test)]
pub(crate) mod test_provider {
    use super::*;

    #[derive(Debug, Default)]
    pub(crate) struct InMemoryProvider {
        pub(crate) entries: Vec<(ItemAttributes, Vec<u8>)>,
        pub(crate) next_index: u64,
        pub(crate) unlock_calls: u64,
        pub(crate) delete_calls: u64,
        pub(crate) locked: bool,
        pub(crate) delete_failure: bool,
    }

    impl InMemoryProvider {
        pub(crate) fn new() -> Self {
            Self {
                entries: Vec::new(),
                next_index: 0,
                unlock_calls: 0,
                delete_calls: 0,
                locked: false,
                delete_failure: false,
            }
        }

        pub(crate) fn set_locked(&mut self, locked: bool) {
            self.locked = locked;
        }

        /// Force the next deletion to fail (deterministic removal boundary
        /// injection; never touches a real keyring).
        pub(crate) fn set_delete_failure(&mut self, fail: bool) {
            self.delete_failure = fail;
        }

        pub(crate) fn probe(&self) -> ProbeOutcome {
            if self.locked {
                ProbeOutcome::ConnectedLocked
            } else {
                ProbeOutcome::ConnectedUnlocked
            }
        }

        pub(crate) fn unlock_default_collection(&mut self) -> Result<(), ProviderFailure> {
            self.unlock_calls += 1;
            if self.locked {
                Err(ProviderFailure::Locked)
            } else {
                Ok(())
            }
        }

        pub(crate) fn search(&self, attributes: &ItemAttributes) -> Vec<StoredItem> {
            self.entries
                .iter()
                .enumerate()
                .filter(|(_, (attrs, _))| attrs == attributes)
                .map(|(i, _)| StoredItem {
                    item_index: i as u64,
                    attributes: attributes.to_map(),
                })
                .collect()
        }

        pub(crate) fn read_secret(
            &self,
            item: &StoredItem,
        ) -> Result<Zeroizing<Vec<u8>>, ProviderFailure> {
            self.entries
                .get(item.item_index as usize)
                .map(|(_, secret)| Zeroizing::new(secret.clone()))
                .ok_or(ProviderFailure::Deleted)
        }

        pub(crate) fn create_item(
            &mut self,
            attributes: &ItemAttributes,
            secret: &[u8],
        ) -> Result<StoredItem, ProviderFailure> {
            let index = self.next_index;
            self.next_index += 1;
            self.entries.push((attributes.clone(), secret.to_vec()));
            Ok(StoredItem {
                item_index: index,
                attributes: attributes.to_map(),
            })
        }

        pub(crate) fn delete_item(&mut self, item: &StoredItem) -> Result<(), ProviderFailure> {
            if self.delete_failure {
                return Err(ProviderFailure::Io);
            }
            let Some((i, _)) = self
                .entries
                .iter()
                .enumerate()
                .find(|(_, (attrs, _))| attrs.to_map() == item.attributes)
            else {
                return Err(ProviderFailure::Deleted);
            };
            self.entries.remove(i);
            self.delete_calls += 1;
            Ok(())
        }
    }

    impl crate::ubuntu_vault::lifecycle::removal::KeyringVaultOps for InMemoryProvider {
        async fn delete_active_and_staged(&mut self) -> Result<bool, ProviderFailure> {
            let active = ItemAttributes::active(ReleaseChannel::Production);
            let staged = ItemAttributes::staged(ReleaseChannel::Production);
            for attributes in [active, staged] {
                let items = self.search(&attributes);
                for item in items {
                    self.delete_item(&item)?;
                }
            }
            self.verify_absent().await
        }

        async fn verify_absent(&mut self) -> Result<bool, ProviderFailure> {
            let active = ItemAttributes::active(ReleaseChannel::Production);
            let staged = ItemAttributes::staged(ReleaseChannel::Production);
            Ok(self.search(&active).is_empty() && self.search(&staged).is_empty())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_attrs() -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        map.insert(ATTR_APPLICATION_ID.to_string(), APPLICATION_ID.to_string());
        map.insert(ATTR_RELEASE_CHANNEL.to_string(), "production".to_string());
        map.insert(ATTR_PURPOSE.to_string(), ITEM_PURPOSE.to_string());
        map.insert(
            ATTR_WRAPPER_FORMAT_VERSION.to_string(),
            WRAPPER_FORMAT_VERSION.to_string(),
        );
        map
    }

    #[test]
    fn attributes_are_identity_free_and_fixed() {
        let attrs = ItemAttributes::active(ReleaseChannel::Production);
        let map = attrs.to_map();
        assert_eq!(map, fixed_attrs());
        // No identity/user/endpoint vocabulary anywhere.
        let serialized = format!("{map:?}");
        for forbidden in [
            "alias", "address", "user", "uid", "mnemonic", "endpoint", "network", "host", "profile",
        ] {
            assert!(!serialized.contains(forbidden), "leaked {forbidden}");
        }
        assert!(attrs.matches(&map));
    }

    #[test]
    fn channels_never_collide() {
        let prod = ItemAttributes::active(ReleaseChannel::Production).to_map();
        let dev = ItemAttributes::active(ReleaseChannel::Development).to_map();
        let test = ItemAttributes::active(ReleaseChannel::Test).to_map();
        assert_ne!(prod, dev);
        assert_ne!(dev, test);
        assert_ne!(prod, test);
        // Staged and active purposes are distinct within a channel.
        let active = ItemAttributes::active(ReleaseChannel::Production);
        let staged = ItemAttributes::staged(ReleaseChannel::Production);
        assert_ne!(active.to_map(), staged.to_map());
    }

    #[test]
    fn active_and_staged_are_distinguishable() {
        let active = StoredItem {
            item_index: 0,
            attributes: ItemAttributes::active(ReleaseChannel::Production).to_map(),
        };
        let staged = StoredItem {
            item_index: 1,
            attributes: ItemAttributes::staged(ReleaseChannel::Production).to_map(),
        };
        assert!(active.is_active());
        assert!(!active.is_staged());
        assert!(staged.is_staged());
        assert!(!staged.is_active());
    }

    #[test]
    fn wrapped_key_round_trips_in_memory_provider() {
        let mut provider = test_provider::InMemoryProvider::new();
        let attrs = ItemAttributes::active(ReleaseChannel::Production);
        provider
            .create_item(&attrs, b"0123456789abcdef0123456789abcdef")
            .unwrap();
        let found = provider.search(&attrs);
        assert_eq!(found.len(), 1);
        let secret = provider.read_secret(&found[0]).unwrap();
        assert_eq!(&*secret, b"0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn delete_removes_only_matching_vocabulary() {
        let mut provider = test_provider::InMemoryProvider::new();
        let active = ItemAttributes::active(ReleaseChannel::Production);
        let staged = ItemAttributes::staged(ReleaseChannel::Production);
        provider
            .create_item(&active, b"active-key-32-bytes-00000000")
            .unwrap();
        provider
            .create_item(&staged, b"staged-key-32-bytes-000000000")
            .unwrap();
        let active_items = provider.search(&active);
        assert_eq!(active_items.len(), 1);
        provider.delete_item(&active_items[0]).unwrap();
        assert!(provider.search(&active).is_empty());
        // Staged entry preserved (different purpose vocabulary).
        assert_eq!(provider.search(&staged).len(), 1);
    }

    #[test]
    fn locked_provider_reports_locked_and_unlock_is_explicit() {
        let mut provider = test_provider::InMemoryProvider::new();
        provider.set_locked(true);
        assert_eq!(provider.probe(), ProbeOutcome::ConnectedLocked);
        assert_eq!(
            provider.unlock_default_collection(),
            Err(ProviderFailure::Locked)
        );
        provider.set_locked(false);
        assert_eq!(provider.unlock_default_collection(), Ok(()));
        assert_eq!(provider.unlock_calls, 2);
    }

    #[test]
    fn staged_and_active_cardinality_one_each() {
        // Steady state: one active; rotation: one active + one staged.
        let mut provider = test_provider::InMemoryProvider::new();
        let active = ItemAttributes::active(ReleaseChannel::Production);
        provider
            .create_item(&active, b"key-1-32-bytes-0000000000000")
            .unwrap();
        assert_eq!(provider.search(&active).len(), 1);
        let staged = ItemAttributes::staged(ReleaseChannel::Production);
        provider
            .create_item(&staged, b"key-2-32-bytes-0000000000000")
            .unwrap();
        assert_eq!(provider.search(&active).len(), 1);
        assert_eq!(provider.search(&staged).len(), 1);
    }
}
