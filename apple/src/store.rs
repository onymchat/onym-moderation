//! Durable state: enrollments, countersigned mandates, verdicts, and
//! the append-only write log.
//!
//! SQLite, because a single droplet serves one interface vendor and the
//! whole dataset is small; the schema is the interesting part, not the
//! engine.
//!
//! The **write log** is this profile's substitute for a platform-level
//! proof that the vendor wrote faithfully (Moderation-DeviceCheck.md §4
//! requirement 2, §8 gap 3). Every `update_two_bits` call is recorded
//! against the verdict hash (or the expiry/deadline rule) that
//! authorized it, and each row carries the hash of the previous row, so
//! an auditor can detect a deleted or reordered entry rather than
//! having to trust the table.

use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::Error;
use crate::util;

pub struct Store {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct Enrollment {
    pub device_binding: String,
}

#[derive(Debug, Clone)]
pub struct MandateRecord {
    pub mandate_ref: String,
    pub user_key: String,
    pub authority: String,
    pub device_binding: String,
    pub manifest_hash: String,
    pub classes: Vec<String>,
}

/// A verdict as stored: the raw bytes (so the signature stays
/// verifiable and the object re-servable verbatim), plus the fields the
/// gate and reconciliation paths query on.
#[derive(Debug, Clone)]
pub struct StoredVerdict {
    pub verdict_ref: String,
    pub case_id: String,
    /// The verdict's own signed `decidedAt`. The fold orders by this,
    /// not by arrival: the authority decides the sequence, and delivery
    /// can reorder it.
    pub decided_at: String,
    pub mandate_ref: String,
    pub device_binding: String,
    pub raw: Vec<u8>,
    pub disposition: String,
    pub ban_expires: Option<String>,
    pub execute_after: Option<String>,
    /// False until the marks it authorizes have actually been written.
    pub executed: bool,
    pub superseded: bool,
}

#[derive(Debug, Clone)]
pub struct WriteLogEntry {
    pub sequence: i64,
    pub recorded_at: String,
    pub device_binding: String,
    /// The verdict hash, or a rule name for default-driven clears
    /// (`expiry`, `decision-deadline-default`, `reversal`).
    pub authorized_by: String,
    pub case_open: bool,
    pub banned: bool,
    pub outcome: String,
    pub previous_hash: String,
    pub entry_hash: String,
}

impl Store {
    pub fn open(path: &str) -> Result<Self, Error> {
        let conn = Connection::open(path)
            .map_err(|e| Error::Internal(format!("open store at {path}: {e}")))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| Error::Internal(format!("set WAL: {e}")))?;
        conn.pragma_update(None, "foreign_keys", "ON").ok();
        let store = Self { conn: Mutex::new(conn) };
        store.migrate()?;
        Ok(store)
    }

    #[cfg(test)]
    pub fn in_memory() -> Result<Self, Error> {
        let conn = Connection::open_in_memory()
            .map_err(|e| Error::Internal(format!("open in-memory store: {e}")))?;
        let store = Self { conn: Mutex::new(conn) };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS enrollments (
                device_binding TEXT PRIMARY KEY,
                user_key       TEXT NOT NULL,
                created_at     TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS mandates (
                mandate_ref    TEXT PRIMARY KEY,
                user_key       TEXT NOT NULL,
                authority      TEXT NOT NULL,
                device_binding TEXT NOT NULL,
                manifest_hash  TEXT NOT NULL,
                classes        TEXT NOT NULL,
                raw            BLOB NOT NULL,
                created_at     TEXT NOT NULL,
                -- The consented manifest's exact bytes, learned when a
                -- verdict first arrives carrying a manifest whose hash
                -- matches `manifest_hash`. Holding it lets the gate
                -- derive real case deadlines from consented windows
                -- instead of inventing them.
                manifest_raw   BLOB
            );
            CREATE INDEX IF NOT EXISTS mandates_by_device
                ON mandates (device_binding);

            -- Session signatures are single-use within their freshness
            -- window, so a captured enroll or gate-check body cannot be
            -- replayed even before its timestamp goes stale.
            CREATE TABLE IF NOT EXISTS seen_signatures (
                signature  TEXT PRIMARY KEY,
                seen_at    TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS verdicts (
                verdict_ref    TEXT PRIMARY KEY,
                case_id        TEXT NOT NULL,
                mandate_ref    TEXT NOT NULL,
                device_binding TEXT NOT NULL,
                disposition    TEXT NOT NULL,
                ban_expires    TEXT,
                execute_after  TEXT,
                executed       INTEGER NOT NULL DEFAULT 0,
                superseded     INTEGER NOT NULL DEFAULT 0,
                raw            BLOB NOT NULL,
                received_at    TEXT NOT NULL,
                -- The verdict's own signed `decidedAt`. Causality
                -- belongs to the authority that decided, not to the
                -- order packets happened to arrive in: a ban and its
                -- reversal can be committed in order and delivered out
                -- of it, and folding by arrival let the ban come back
                -- after the reversal that lifted it.
                decided_at     TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS verdicts_by_device
                ON verdicts (device_binding);

            -- Append-only. Nothing in the service updates or deletes a
            -- row here; `previous_hash` chains them so removal shows.
            CREATE TABLE IF NOT EXISTS write_log (
                sequence       INTEGER PRIMARY KEY AUTOINCREMENT,
                recorded_at    TEXT NOT NULL,
                device_binding TEXT NOT NULL,
                authorized_by  TEXT NOT NULL,
                case_open      INTEGER NOT NULL,
                banned         INTEGER NOT NULL,
                outcome        TEXT NOT NULL,
                previous_hash  TEXT NOT NULL,
                entry_hash     TEXT NOT NULL
            );
            "#,
        )
        .map_err(|e| Error::Internal(format!("migrate: {e}")))?;

        // `CREATE TABLE IF NOT EXISTS` does nothing to a table that
        // already exists, so a column added above never reaches a store
        // opened by an earlier build — and every read selecting it then
        // fails. On a deployment holding live marks that means coming
        // back up dead.
        // One entry today; the list is the shape the next column will
        // need, and forgetting to build it is how the authority's
        // stores nearly came back up dead.
        let added: &[(&str, &str, &str)] = &[("verdicts", "decided_at", "TEXT NOT NULL DEFAULT ''")];
        for (table, column, definition) in added {
            Self::add_column(&conn, table, column, definition)?;
        }
        Ok(())
    }

    /// Add a column, treating "already there" as success. SQLite has no
    /// `ADD COLUMN IF NOT EXISTS`; the duplicate-column error is the
    /// check.
    fn add_column(
        conn: &Connection,
        table: &str,
        column: &str,
        definition: &str,
    ) -> Result<(), Error> {
        match conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"), []) {
            Ok(_) => {
                tracing::info!(%table, %column, "added column to an existing store");
                Ok(())
            }
            Err(e) if e.to_string().contains("duplicate column name") => Ok(()),
            Err(e) => Err(Error::Internal(format!("migrate {table}.{column}: {e}"))),
        }
    }

    // ─── Enrollments ─────────────────────────────────────────────────

    /// Read-or-create, keyed on the identity. The binding must be
    /// stable: one that churns would sever every mandate's
    /// `deviceBinding` on the next launch.
    pub fn enrollment_for(&self, user_key: &str, now: &str) -> Result<Enrollment, Error> {
        let conn = self.conn.lock().unwrap();
        let existing: Option<String> = conn
            .query_row(
                "SELECT device_binding FROM enrollments WHERE user_key = ?1",
                params![user_key],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(device_binding) = existing {
            return Ok(Enrollment { device_binding });
        }
        let device_binding = format!("enrollment:{}", uuid::Uuid::new_v4());
        conn.execute(
            "INSERT INTO enrollments (device_binding, user_key, created_at) VALUES (?1, ?2, ?3)",
            params![device_binding, user_key, now],
        )?;
        Ok(Enrollment { device_binding })
    }

    // ─── Session replay ──────────────────────────────────────────────

    /// Record a session signature, returning false if it has been seen
    /// before. The freshness window bounds how long entries matter, so
    /// anything older than `retain_before` is swept on the way past.
    pub fn claim_signature(
        &self,
        signature: &str,
        now: &str,
        retain_before: &str,
    ) -> Result<bool, Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM seen_signatures WHERE seen_at < ?1",
            params![retain_before],
        )?;
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO seen_signatures (signature, seen_at) VALUES (?1, ?2)",
            params![signature, now],
        )?;
        Ok(inserted == 1)
    }

    // ─── Mandates ────────────────────────────────────────────────────

    pub fn put_mandate(&self, record: &MandateRecord, raw: &[u8], now: &str) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO mandates
             (mandate_ref, user_key, authority, device_binding, manifest_hash, classes, raw, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                record.mandate_ref,
                record.user_key,
                record.authority,
                record.device_binding,
                record.manifest_hash,
                record.classes.join(","),
                raw,
                now
            ],
        )?;
        Ok(())
    }

    /// Pin the consented manifest's exact bytes to a mandate. Called
    /// only after the caller has checked they hash to the mandate's
    /// `manifest_hash`, so this can never store a substituted manifest.
    pub fn attach_manifest(&self, mandate_ref: &str, manifest_raw: &[u8]) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE mandates SET manifest_raw = ?1 WHERE mandate_ref = ?2 AND manifest_raw IS NULL",
            params![manifest_raw, mandate_ref],
        )?;
        Ok(())
    }

    pub fn manifest_for_mandate(&self, mandate_ref: &str) -> Result<Option<Vec<u8>>, Error> {
        let conn = self.conn.lock().unwrap();
        let raw = conn
            .query_row(
                "SELECT manifest_raw FROM mandates WHERE mandate_ref = ?1",
                params![mandate_ref],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .flatten();
        Ok(raw)
    }

    pub fn mandate(&self, mandate_ref: &str) -> Result<Option<MandateRecord>, Error> {
        let conn = self.conn.lock().unwrap();
        let record = conn
            .query_row(
                "SELECT mandate_ref, user_key, authority, device_binding, manifest_hash, classes
                 FROM mandates WHERE mandate_ref = ?1",
                params![mandate_ref],
                |row| {
                    let classes: String = row.get(5)?;
                    Ok(MandateRecord {
                        mandate_ref: row.get(0)?,
                        user_key: row.get(1)?,
                        authority: row.get(2)?,
                        device_binding: row.get(3)?,
                        manifest_hash: row.get(4)?,
                        classes: classes
                            .split(',')
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                            .collect(),
                    })
                },
            )
            .optional()?;
        Ok(record)
    }

    /// The device this identity most recently enrolled, if any.
    pub fn device_binding_for_user(&self, user_key: &str) -> Result<Option<String>, Error> {
        let conn = self.conn.lock().unwrap();
        let binding = conn
            .query_row(
                "SELECT device_binding FROM enrollments WHERE user_key = ?1",
                params![user_key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(binding)
    }

    // ─── Verdicts ────────────────────────────────────────────────────

    pub fn put_verdict(&self, verdict: &StoredVerdict, now: &str) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        let existing: Option<Vec<u8>> = conn
            .query_row(
                "SELECT raw FROM verdicts WHERE verdict_ref = ?1",
                params![verdict.verdict_ref],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(raw) = existing {
            if raw == verdict.raw {
                // Delivery is at-least-once. An exact retry must not
                // reset `executed`, `superseded`, or receipt ordering.
                return Ok(());
            }
            return Err(Error::VerdictInvalid(format!(
                "verdictRef {:?} is already on file with different contents",
                verdict.verdict_ref
            )));
        }
        conn.execute(
            "INSERT INTO verdicts
             (verdict_ref, case_id, mandate_ref, device_binding, disposition,
              ban_expires, execute_after, executed, superseded, raw, received_at, decided_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                verdict.verdict_ref,
                verdict.case_id,
                verdict.mandate_ref,
                verdict.device_binding,
                verdict.disposition,
                verdict.ban_expires,
                verdict.execute_after,
                verdict.executed as i32,
                verdict.superseded as i32,
                verdict.raw,
                now,
                verdict.decided_at
            ],
        )?;
        Ok(())
    }

    pub fn mark_executed(&self, verdict_ref: &str) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE verdicts SET executed = 1 WHERE verdict_ref = ?1",
            params![verdict_ref],
        )?;
        Ok(())
    }

    /// Every verdict for a device, newest **decided** first.
    ///
    /// Ordered by the authority's signed `decidedAt`, not by when the
    /// verdict happened to arrive. Delivery is at-least-once and not
    /// single-flight, so a ban and the reversal that lifts it can be
    /// committed in order and land out of it — and ordering by arrival
    /// let the ban become the newest fold input again and reinstate
    /// itself after being reversed. The same shape let a stale
    /// `open-case` land after a dismissal and reopen the case.
    ///
    /// `received_at` and `rowid` remain as tie-breaks, so ordering is
    /// still total when two verdicts share a `decidedAt`.
    pub fn verdicts_for_device(&self, device_binding: &str) -> Result<Vec<StoredVerdict>, Error> {
        let conn = self.conn.lock().unwrap();
        // `rowid` breaks ties when two verdicts land in the same second,
        // so ordering is total rather than merely mostly-ordered.
        let mut statement = conn.prepare(
            "SELECT verdict_ref, case_id, mandate_ref, device_binding, raw, disposition,
                    ban_expires, execute_after, executed, superseded, decided_at
             FROM verdicts WHERE device_binding = ?1
             ORDER BY decided_at DESC, received_at DESC, rowid DESC",
        )?;
        let rows = statement.query_map(params![device_binding], |row| {
            Ok(StoredVerdict {
                verdict_ref: row.get(0)?,
                case_id: row.get(1)?,
                mandate_ref: row.get(2)?,
                device_binding: row.get(3)?,
                raw: row.get(4)?,
                disposition: row.get(5)?,
                ban_expires: row.get(6)?,
                execute_after: row.get(7)?,
                executed: row.get::<_, i32>(8)? != 0,
                superseded: row.get::<_, i32>(9)? != 0,
                decided_at: row.get(10)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Mark the interim `open-case` verdict for a case as superseded by
    /// its terminal verdict.
    pub fn supersede_open_case(&self, case_id: &str) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE verdicts SET superseded = 1
             WHERE case_id = ?1 AND disposition = 'open-case'",
            params![case_id],
        )?;
        Ok(())
    }

    // ─── Write log ───────────────────────────────────────────────────

    /// Append one entry, chaining it to the previous. Called for every
    /// `update_two_bits`, successful or not — a refused write is as
    /// interesting to an auditor as a completed one.
    pub fn append_write_log(
        &self,
        device_binding: &str,
        authorized_by: &str,
        case_open: bool,
        banned: bool,
        outcome: &str,
        now: &str,
    ) -> Result<WriteLogEntry, Error> {
        let conn = self.conn.lock().unwrap();
        let previous_hash: String = conn
            .query_row(
                "SELECT entry_hash FROM write_log ORDER BY sequence DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or_else(|| "genesis".to_string());

        // The chain covers every field, so altering any of them —
        // including which verdict authorized the write — breaks it.
        let preimage = format!(
            "{previous_hash}|{now}|{device_binding}|{authorized_by}|{case_open}|{banned}|{outcome}"
        );
        let entry_hash = util::sha256_hex(preimage.as_bytes());

        conn.execute(
            "INSERT INTO write_log
             (recorded_at, device_binding, authorized_by, case_open, banned, outcome, previous_hash, entry_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                now,
                device_binding,
                authorized_by,
                case_open as i32,
                banned as i32,
                outcome,
                previous_hash,
                entry_hash
            ],
        )?;
        let sequence = conn.last_insert_rowid();
        Ok(WriteLogEntry {
            sequence,
            recorded_at: now.to_string(),
            device_binding: device_binding.to_string(),
            authorized_by: authorized_by.to_string(),
            case_open,
            banned,
            outcome: outcome.to_string(),
            previous_hash,
            entry_hash,
        })
    }

    pub fn write_log(&self, limit: i64) -> Result<Vec<WriteLogEntry>, Error> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(
            "SELECT sequence, recorded_at, device_binding, authorized_by, case_open, banned,
                    outcome, previous_hash, entry_hash
             FROM write_log ORDER BY sequence ASC LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit], |row| {
            Ok(WriteLogEntry {
                sequence: row.get(0)?,
                recorded_at: row.get(1)?,
                device_binding: row.get(2)?,
                authorized_by: row.get(3)?,
                case_open: row.get::<_, i32>(4)? != 0,
                banned: row.get::<_, i32>(5)? != 0,
                outcome: row.get(6)?,
                previous_hash: row.get(7)?,
                entry_hash: row.get(8)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Recompute the chain. Returns the sequence of the first entry
    /// that doesn't match, if any — what an audit-seat attestation
    /// would check.
    pub fn verify_write_log(&self) -> Result<Option<i64>, Error> {
        let entries = self.write_log(i64::MAX)?;
        let mut previous = "genesis".to_string();
        for entry in entries {
            if entry.previous_hash != previous {
                return Ok(Some(entry.sequence));
            }
            let preimage = format!(
                "{}|{}|{}|{}|{}|{}|{}",
                entry.previous_hash,
                entry.recorded_at,
                entry.device_binding,
                entry.authorized_by,
                entry.case_open,
                entry.banned,
                entry.outcome
            );
            if util::sha256_hex(preimage.as_bytes()) != entry.entry_hash {
                return Ok(Some(entry.sequence));
            }
            previous = entry.entry_hash;
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_is_stable_per_identity() {
        let store = Store::in_memory().unwrap();
        let first = store.enrollment_for("onym:key:aa", "2026-08-08T00:00:00Z").unwrap();
        let second = store.enrollment_for("onym:key:aa", "2026-08-08T00:01:00Z").unwrap();
        assert_eq!(first.device_binding, second.device_binding);

        let other = store.enrollment_for("onym:key:bb", "2026-08-08T00:02:00Z").unwrap();
        assert_ne!(first.device_binding, other.device_binding);
    }

    #[test]
    fn write_log_chains_and_verifies() {
        let store = Store::in_memory().unwrap();
        store
            .append_write_log("d1", "verdict-a", false, true, "ok", "2026-08-08T00:00:00Z")
            .unwrap();
        store
            .append_write_log("d1", "expiry", false, false, "ok", "2026-08-09T00:00:00Z")
            .unwrap();

        let entries = store.write_log(10).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].previous_hash, "genesis");
        assert_eq!(entries[1].previous_hash, entries[0].entry_hash);
        assert_eq!(store.verify_write_log().unwrap(), None);
    }

    #[test]
    fn session_signatures_are_single_use() {
        let store = Store::in_memory().unwrap();
        let retain_before = "2026-08-08T00:00:00Z";
        assert!(store
            .claim_signature("sig-a", "2026-08-08T12:00:00Z", retain_before)
            .unwrap());
        // A replay presents the same signature bytes.
        assert!(!store
            .claim_signature("sig-a", "2026-08-08T12:00:01Z", retain_before)
            .unwrap());
        assert!(store
            .claim_signature("sig-b", "2026-08-08T12:00:02Z", retain_before)
            .unwrap());
    }

    /// Entries older than the freshness window are swept, so the table
    /// stays bounded — and a signature that old is rejected on
    /// timestamp anyway.
    #[test]
    fn old_session_signatures_are_swept() {
        let store = Store::in_memory().unwrap();
        assert!(store
            .claim_signature("sig-a", "2026-08-08T12:00:00Z", "2026-08-08T00:00:00Z")
            .unwrap());
        assert!(store
            .claim_signature("sig-b", "2026-08-09T12:00:00Z", "2026-08-09T00:00:00Z")
            .unwrap());
        // sig-a was swept by the second call's retention bound.
        assert!(store
            .claim_signature("sig-a", "2026-08-09T12:00:01Z", "2026-08-09T00:00:00Z")
            .unwrap());
    }

    #[test]
    fn manifest_attaches_once_and_reads_back() {
        let store = Store::in_memory().unwrap();
        let record = MandateRecord {
            mandate_ref: "m1".into(),
            user_key: "onym:key:aa".into(),
            authority: "onym:component:a".into(),
            device_binding: "d1".into(),
            manifest_hash: "hash".into(),
            classes: vec!["csam".into()],
        };
        store.put_mandate(&record, b"{}", "2026-08-08T00:00:00Z").unwrap();
        assert_eq!(store.manifest_for_mandate("m1").unwrap(), None);

        store.attach_manifest("m1", b"{\"a\":1}").unwrap();
        assert_eq!(store.manifest_for_mandate("m1").unwrap().unwrap(), b"{\"a\":1}");

        // Attach is write-once: a later call cannot swap the manifest
        // a mandate is understood to have consented to.
        store.attach_manifest("m1", b"{\"a\":2}").unwrap();
        assert_eq!(store.manifest_for_mandate("m1").unwrap().unwrap(), b"{\"a\":1}");
    }

    /// The point of the chain: a doctored row is detectable without
    /// trusting the table.
    #[test]
    fn tampering_with_an_entry_is_detected() {
        let store = Store::in_memory().unwrap();
        store
            .append_write_log("d1", "verdict-a", false, true, "ok", "2026-08-08T00:00:00Z")
            .unwrap();
        store
            .append_write_log("d1", "expiry", false, false, "ok", "2026-08-09T00:00:00Z")
            .unwrap();

        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE write_log SET authorized_by = 'forged' WHERE sequence = 1",
                [],
            )
            .unwrap();
        }
        assert_eq!(store.verify_write_log().unwrap(), Some(1));
    }
}
