//! Durable state: registered mandates, reporter track records, reports,
//! cases, and issued verdicts.

use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::Error;

pub struct Store {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
/// Everything one decision writes. Grouped so that issuing a verdict,
/// moving the case, recording the event, and adjusting reporters'
/// standing cannot drift apart into separate calls that a crash could
/// interleave.
pub struct Decision<'a> {
    pub case: &'a CaseRecord,
    pub verdict_ref: &'a str,
    pub disposition: &'a str,
    pub raw: &'a [u8],
    pub at: &'a str,
    pub event_kind: &'a str,
    /// Free text for the case log — a verdict reference, or why the
    /// decision happened without a moderator.
    pub event_detail: &'a str,
    /// Reporters whose track record this decision moves. Empty when the
    /// decision says nothing about them: a deadline dismissal is the
    /// authority's failure, and a reversal is its own error.
    pub credited_reporters: &'a [String],
    /// The stage the caller checked before building this verdict, and
    /// the disposition it expected to find. Re-asserted inside the
    /// transaction: the guards run against a case read under one lock
    /// and the write happens under another, so a moderator's decision
    /// racing the autonomous sweep would otherwise produce two signed
    /// verdicts for one case and credit its reporters twice.
    pub expect_stage: &'a str,
    pub expect_disposition: Option<&'a str>,
}

/// A verdict awaiting delivery, carrying the manifest bytes the case
/// was judged under. `consented_manifest` is `None` only for cases
/// whose mandate predates manifest snapshotting.
pub struct UndeliveredVerdict {
    pub verdict_ref: String,
    pub raw: Vec<u8>,
    pub consented_manifest: Option<Vec<u8>>,
}

pub struct MandateRecord {
    pub mandate_ref: String,
    pub user_key: String,
    pub device_binding: String,
    pub classes: Vec<String>,
    /// The manifest this mandate consented to. Case terms are read
    /// from these bytes, never from whatever is published now.
    pub manifest_hash: String,
}

/// One case, in the lifecycle of Moderation.md §10.
///
/// `stage` is the state machine: `open` (notice served, response
/// window running) → `decided`. Terminal stages record how it ended,
/// because "dismissed by deadline" and "dismissed on the record" are
/// different facts about the authority.
#[derive(Debug, Clone)]
pub struct CaseRecord {
    pub case_id: String,
    pub accused: String,
    pub reporter: String,
    pub class_id: String,
    pub mandate_ref: String,
    pub device_binding: String,
    pub stage: String,
    pub opened_at: String,
    pub response_deadline: String,
    pub decision_deadline: String,
    pub responded: bool,
    pub disposition: Option<String>,
    pub appeal_deadline: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ReporterRecord {
    pub upheld: i64,
    pub dismissed: i64,
}

impl ReporterRecord {
    /// Intake weight from the authority-local track record. Published
    /// as the manifest's reputation policy; deliberately simple here,
    /// and deliberately *not* a bounty — paid reporting industrialises
    /// false accusation (§7.2).
    pub fn weight(&self) -> f64 {
        let total = (self.upheld + self.dismissed) as f64;
        if total == 0.0 {
            // A reporter with no record is heard, just not prioritised.
            return 1.0;
        }
        1.0 + (self.upheld as f64 / total)
    }
}

impl Store {
    pub fn open(path: &str) -> Result<Self, Error> {
        let conn = Connection::open(path)
            .map_err(|e| Error::Internal(format!("open store at {path}: {e}")))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| Error::Internal(format!("set WAL: {e}")))?;
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
            -- Every manifest this authority has published, by hash.
            -- A mandate consents to *exact bytes*; when those bytes are
            -- superseded the mandate still names the old hash, so the
            -- terms a live case is judged by must come from here and
            -- not from whatever is currently published.
            CREATE TABLE IF NOT EXISTS manifests (
                manifest_hash TEXT PRIMARY KEY,
                raw           BLOB NOT NULL,
                first_seen_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS mandates (
                mandate_ref    TEXT PRIMARY KEY,
                user_key       TEXT NOT NULL,
                device_binding TEXT NOT NULL,
                classes        TEXT NOT NULL,
                raw            BLOB NOT NULL,
                accepted_at    TEXT NOT NULL,
                -- The manifest this mandate pinned.
                manifest_hash  TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS mandates_by_user ON mandates (user_key);

            CREATE TABLE IF NOT EXISTS reporters (
                user_key  TEXT PRIMARY KEY,
                upheld    INTEGER NOT NULL DEFAULT 0,
                dismissed INTEGER NOT NULL DEFAULT 0
            );

            -- `report_id` is client-chosen, so it identifies a report
            -- only *within* a reporter. Making it the global primary
            -- key would let anyone overwrite another reporter's
            -- evidence record by picking their id.
            CREATE TABLE IF NOT EXISTS reports (
                report_id  TEXT NOT NULL,
                reporter   TEXT NOT NULL,
                accused    TEXT NOT NULL,
                class_id   TEXT NOT NULL,
                case_id    TEXT,
                weight     REAL NOT NULL,
                raw        BLOB NOT NULL,
                filed_at   TEXT NOT NULL,
                PRIMARY KEY (reporter, report_id)
            );
            CREATE INDEX IF NOT EXISTS reports_by_case ON reports (case_id);

            CREATE TABLE IF NOT EXISTS cases (
                case_id           TEXT PRIMARY KEY,
                accused           TEXT NOT NULL,
                reporter          TEXT NOT NULL,
                class_id          TEXT NOT NULL,
                mandate_ref       TEXT NOT NULL,
                device_binding    TEXT NOT NULL,
                stage             TEXT NOT NULL,
                opened_at         TEXT NOT NULL,
                response_deadline TEXT NOT NULL,
                decision_deadline TEXT NOT NULL,
                responded         INTEGER NOT NULL DEFAULT 0,
                disposition       TEXT,
                appeal_deadline   TEXT
            );
            CREATE INDEX IF NOT EXISTS cases_by_stage ON cases (stage);
            -- At most one open case per (accused, class). Intake checks
            -- for an existing open case before opening one, but that
            -- check and the insert are separate statements: two reports
            -- arriving together can both find none and both open a
            -- case, each setting a mark before anyone has decided
            -- anything. The database is the only place that race can
            -- actually be settled.
            CREATE UNIQUE INDEX IF NOT EXISTS one_open_case_per_accused_class
                ON cases (accused, class_id) WHERE stage = 'open';

            -- The accused's responses, kept whole. Discarding the
            -- counter-evidence would mean deciding, and later
            -- reviewing, without the thing the accused offered in their
            -- own defence.
            CREATE TABLE IF NOT EXISTS responses (
                sequence  INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id   TEXT NOT NULL,
                raw       BLOB NOT NULL,
                late      INTEGER NOT NULL DEFAULT 0,
                filed_at  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS responses_by_case ON responses (case_id);

            CREATE TABLE IF NOT EXISTS case_events (
                sequence   INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id    TEXT NOT NULL,
                at         TEXT NOT NULL,
                kind       TEXT NOT NULL,
                detail     TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS verdicts (
                verdict_ref TEXT PRIMARY KEY,
                case_id     TEXT NOT NULL,
                disposition TEXT NOT NULL,
                raw         BLOB NOT NULL,
                issued_at   TEXT NOT NULL,
                delivered   INTEGER NOT NULL DEFAULT 0,
                -- How many delivery attempts have been refused, and
                -- what the interface last said. A verdict the interface
                -- rejects on its shape will be rejected identically
                -- forever; without a count it just re-POSTs every sweep
                -- and the mismatch shows up as a log line nobody reads
                -- rather than as a thing that is stuck.
                attempts      INTEGER NOT NULL DEFAULT 0,
                -- Counted separately from `attempts`, because only
                -- these justify giving up: an interface that was
                -- unreachable for three sweeps must not make the next
                -- 4xx the last straw.
                refusals      INTEGER NOT NULL DEFAULT 0,
                last_error    TEXT,
                -- Set when the interface has refused the verdict's
                -- shape enough times that retrying is pointless. Not a
                -- deletion: the verdict stands, and the mark it should
                -- have moved has not moved, which is exactly what an
                -- operator needs to see.
                undeliverable INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS verdicts_undelivered ON verdicts (delivered);
            "#,
        )
        .map_err(|e| Error::Internal(format!("migrate: {e}")))?;

        // `CREATE TABLE IF NOT EXISTS` does nothing to a table that
        // already exists, so a column added to one of the definitions
        // above never reaches a store that has been opened before.
        // Every read that selects it then fails, which on a deployment
        // holding live cases means the service comes back up dead.
        //
        // So: add columns explicitly, tolerating the duplicate when
        // they are already there. New *tables* are fine above — it is
        // only new columns in old tables that need this.
        for (table, column, definition) in [
            // The manifest a mandate pinned. Without it a case cannot
            // be judged by the terms its accused actually agreed to.
            ("mandates", "manifest_hash", "TEXT NOT NULL DEFAULT ''"),
            // Delivery bookkeeping, so a verdict the interface refuses
            // becomes visibly stuck instead of retrying forever.
            ("verdicts", "attempts", "INTEGER NOT NULL DEFAULT 0"),
            ("verdicts", "refusals", "INTEGER NOT NULL DEFAULT 0"),
            ("verdicts", "last_error", "TEXT"),
            ("verdicts", "undeliverable", "INTEGER NOT NULL DEFAULT 0"),
        ] {
            Self::add_column(&conn, table, column, definition)?;
        }

        Ok(())
    }

    /// Add a column, treating "it is already there" as success.
    ///
    /// SQLite has no `ADD COLUMN IF NOT EXISTS`, and checking
    /// `pragma_table_info` first would be a race with nothing; the
    /// duplicate-column error is the check.
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

    // ─── Mandates ────────────────────────────────────────────────────

    /// Store a mandate together with the exact manifest bytes it
    /// consented to, in one transaction: a mandate whose manifest we
    /// did not keep is a mandate whose terms we cannot honour later.
    pub fn put_mandate(
        &self,
        record: &MandateRecord,
        raw: &[u8],
        manifest_raw: &[u8],
        accepted_at: &str,
    ) -> Result<(), Error> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO manifests (manifest_hash, raw, first_seen_at)
             VALUES (?1, ?2, ?3)",
            params![record.manifest_hash, manifest_raw, accepted_at],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO mandates
             (mandate_ref, user_key, device_binding, classes, raw, accepted_at, manifest_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.mandate_ref,
                record.user_key,
                record.device_binding,
                record.classes.join(","),
                raw,
                accepted_at,
                record.manifest_hash
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The manifest bytes a mandate pinned.
    pub fn manifest_bytes(&self, manifest_hash: &str) -> Result<Option<Vec<u8>>, Error> {
        let conn = self.conn.lock().unwrap();
        let raw = conn
            .query_row(
                "SELECT raw FROM manifests WHERE manifest_hash = ?1",
                params![manifest_hash],
                |row| row.get(0),
            )
            .optional()?;
        Ok(raw)
    }

    fn mandate_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MandateRecord> {
        let classes: String = row.get(3)?;
        Ok(MandateRecord {
            mandate_ref: row.get(0)?,
            user_key: row.get(1)?,
            device_binding: row.get(2)?,
            classes: classes.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect(),
            manifest_hash: row.get(4)?,
        })
    }

    /// The mandate a user signed naming this authority. Its absence is
    /// what `no_jurisdiction` and `reporter_unconsented` mean.
    /// A mandate by its reference — how a case reaches the terms it
    /// must be judged under.
    pub fn mandate(&self, mandate_ref: &str) -> Result<Option<MandateRecord>, Error> {
        let conn = self.conn.lock().unwrap();
        let record = conn
            .query_row(
                "SELECT mandate_ref, user_key, device_binding, classes, manifest_hash
                 FROM mandates WHERE mandate_ref = ?1",
                params![mandate_ref],
                Self::mandate_from_row,
            )
            .optional()?;
        Ok(record)
    }

    pub fn mandate_for_user(&self, user_key: &str) -> Result<Option<MandateRecord>, Error> {
        let conn = self.conn.lock().unwrap();
        let record = conn
            .query_row(
                "SELECT mandate_ref, user_key, device_binding, classes, manifest_hash
                 FROM mandates WHERE user_key = ?1 ORDER BY accepted_at DESC LIMIT 1",
                params![user_key],
                Self::mandate_from_row,
            )
            .optional()?;
        Ok(record)
    }


    // ─── Reporters ───────────────────────────────────────────────────

    pub fn reporter(&self, user_key: &str) -> Result<ReporterRecord, Error> {
        let conn = self.conn.lock().unwrap();
        let record = conn
            .query_row(
                "SELECT upheld, dismissed FROM reporters WHERE user_key = ?1",
                params![user_key],
                |row| Ok(ReporterRecord { upheld: row.get(0)?, dismissed: row.get(1)? }),
            )
            .optional()?
            .unwrap_or_default();
        Ok(record)
    }

    /// Adjust a reporter's authority-local track record. Pseudonymous,
    /// local to this authority, non-transferable — not a market (§7.2).
    ///
    /// Private, and reachable only from `commit_decision`: a track
    /// record may move only as part of a decision that also committed a
    /// signed verdict. Exposed separately it becomes a way to demote a
    /// reporter with no case behind it.
    fn credit_reporter(
        conn: &rusqlite::Connection,
        user_key: &str,
        upheld: bool,
    ) -> Result<(), Error> {
        conn.execute(
            "INSERT INTO reporters (user_key, upheld, dismissed) VALUES (?1, 0, 0)
             ON CONFLICT(user_key) DO NOTHING",
            params![user_key],
        )?;
        let column = if upheld { "upheld" } else { "dismissed" };
        conn.execute(
            &format!("UPDATE reporters SET {column} = {column} + 1 WHERE user_key = ?1"),
            params![user_key],
        )?;
        Ok(())
    }

    // ─── Reports ─────────────────────────────────────────────────────

}

/// What an already-stored report was filed against, for deciding
/// whether a re-file is a replay or a rewrite.
pub struct ExistingReport {
    pub case_id: Option<String>,
    pub raw: Vec<u8>,
}

impl Store {
    /// A report already on file under this (reporter, report_id).
    pub fn report(&self, reporter: &str, report_id: &str) -> Result<Option<ExistingReport>, Error> {
        let conn = self.conn.lock().unwrap();
        let found = conn
            .query_row(
                "SELECT case_id, raw FROM reports WHERE reporter = ?1 AND report_id = ?2",
                params![reporter, report_id],
                |row| Ok(ExistingReport { case_id: row.get(0)?, raw: row.get(1)? }),
            )
            .optional()?;
        Ok(found)
    }

    /// File a report. Insert-only: a stored report is evidence, and
    /// evidence that can be overwritten after the fact — by its own
    /// filer or by anyone who guesses the id — is not evidence. A
    /// replay of identical bytes is handled by the caller as
    /// idempotent; conflicting bytes under a used id are refused here.
    #[allow(clippy::too_many_arguments)]
    pub fn put_report(
        &self,
        report_id: &str,
        reporter: &str,
        accused: &str,
        class_id: &str,
        case_id: Option<&str>,
        weight: f64,
        raw: &[u8],
        filed_at: &str,
    ) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO reports
             (report_id, reporter, accused, class_id, case_id, weight, raw, filed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![report_id, reporter, accused, class_id, case_id, weight, raw, filed_at],
        )?;
        if inserted == 0 {
            return Err(Error::BadRequest(format!(
                "a different report is already on file under reportId {report_id:?}; \
                 report ids are immutable once filed"
            )));
        }
        Ok(())
    }

    /// Attach a stored report to the case it opened or joined.
    pub fn attach_report_to_case(
        &self,
        reporter: &str,
        report_id: &str,
        case_id: &str,
    ) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE reports SET case_id = ?3 WHERE reporter = ?1 AND report_id = ?2",
            params![reporter, report_id, case_id],
        )?;
        Ok(())
    }

    /// Every reporter whose report is attached to this case. A case
    /// that several people reported was upheld or dismissed for all of
    /// them, not just whoever filed first.
    pub fn case_reporters(&self, case_id: &str) -> Result<Vec<String>, Error> {
        let conn = self.conn.lock().unwrap();
        let mut statement =
            conn.prepare("SELECT DISTINCT reporter FROM reports WHERE case_id = ?1 ORDER BY reporter")?;
        let rows = statement.query_map(params![case_id], |row| row.get(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    // ─── Responses ───────────────────────────────────────────────────

    /// Store the accused's response whole, and mark the case as
    /// answered, in one write.
    pub fn put_response(
        &self,
        case: &CaseRecord,
        raw: &[u8],
        late: bool,
        filed_at: &str,
        event_kind: &str,
        event_detail: &str,
    ) -> Result<(), Error> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO responses (case_id, raw, late, filed_at) VALUES (?1, ?2, ?3, ?4)",
            params![case.case_id, raw, late as i32, filed_at],
        )?;
        Self::write_case(&tx, case)?;
        tx.execute(
            "INSERT INTO case_events (case_id, at, kind, detail) VALUES (?1, ?2, ?3, ?4)",
            params![case.case_id, filed_at, event_kind, event_detail],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The accused's responses, oldest first — the counter-evidence a
    /// decision is supposed to be made on.
    pub fn responses(&self, case_id: &str) -> Result<Vec<(Vec<u8>, bool, String)>, Error> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(
            "SELECT raw, late, filed_at FROM responses WHERE case_id = ?1 ORDER BY sequence",
        )?;
        let rows = statement
            .query_map(params![case_id], |row| {
                Ok((row.get(0)?, row.get::<_, i32>(1)? != 0, row.get(2)?))
            })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    // ─── Cases ───────────────────────────────────────────────────────

    fn write_case(conn: &rusqlite::Connection, case: &CaseRecord) -> Result<(), Error> {
        conn.execute(
            "INSERT OR REPLACE INTO cases
             (case_id, accused, reporter, class_id, mandate_ref, device_binding, stage,
              opened_at, response_deadline, decision_deadline, responded, disposition, appeal_deadline)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                case.case_id,
                case.accused,
                case.reporter,
                case.class_id,
                case.mandate_ref,
                case.device_binding,
                case.stage,
                case.opened_at,
                case.response_deadline,
                case.decision_deadline,
                case.responded as i32,
                case.disposition,
                case.appeal_deadline,
            ],
        )?;
        Ok(())
    }

    /// Test-only. In the service a case row moves only inside a
    /// transaction that also writes the verdict justifying the move —
    /// see `open_case_atomically` and `commit_decision`.
    #[cfg(test)]
    pub fn put_case(&self, case: &CaseRecord) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        Self::write_case(&conn, case)
    }

    /// Open a case and issue its interim verdict as one unit. A case
    /// row without its open-case verdict would set a mark the accused
    /// has no signed document for; a verdict without its case would be
    /// a mark nothing can ever clear.
    ///
    /// Returns `Ok(false)` when another case is already open for this
    /// accused and class — the unique index caught a concurrent
    /// opener, and the caller should join that case instead of opening
    /// a second one.
    #[allow(clippy::too_many_arguments)]
    pub fn open_case_atomically(
        &self,
        case: &CaseRecord,
        verdict_ref: &str,
        disposition: &str,
        raw: &[u8],
        at: &str,
        event_detail: &str,
    ) -> Result<bool, Error> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        // Plain INSERT, not INSERT OR REPLACE: the unique partial index
        // is the point, and swallowing its violation would defeat it.
        match tx.execute(
            "INSERT INTO cases
             (case_id, accused, reporter, class_id, mandate_ref, device_binding, stage,
              opened_at, response_deadline, decision_deadline, responded, disposition,
              appeal_deadline)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                case.case_id,
                case.accused,
                case.reporter,
                case.class_id,
                case.mandate_ref,
                case.device_binding,
                case.stage,
                case.opened_at,
                case.response_deadline,
                case.decision_deadline,
                case.responded as i32,
                case.disposition,
                case.appeal_deadline,
            ],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Ok(false);
            }
            Err(e) => return Err(e.into()),
        }
        tx.execute(
            "INSERT OR REPLACE INTO verdicts (verdict_ref, case_id, disposition, raw, issued_at, delivered)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            params![verdict_ref, case.case_id, disposition, raw, at],
        )?;
        tx.execute(
            "INSERT INTO case_events (case_id, at, kind, detail) VALUES (?1, ?2, ?3, ?4)",
            params![case.case_id, at, "case_opened", event_detail],
        )?;
        tx.commit()?;
        Ok(true)
    }

    fn case_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CaseRecord> {
        Ok(CaseRecord {
            case_id: row.get(0)?,
            accused: row.get(1)?,
            reporter: row.get(2)?,
            class_id: row.get(3)?,
            mandate_ref: row.get(4)?,
            device_binding: row.get(5)?,
            stage: row.get(6)?,
            opened_at: row.get(7)?,
            response_deadline: row.get(8)?,
            decision_deadline: row.get(9)?,
            responded: row.get::<_, i32>(10)? != 0,
            disposition: row.get(11)?,
            appeal_deadline: row.get(12)?,
        })
    }

    const CASE_COLUMNS: &'static str = "case_id, accused, reporter, class_id, mandate_ref, \
         device_binding, stage, opened_at, response_deadline, decision_deadline, responded, \
         disposition, appeal_deadline";

    pub fn case(&self, case_id: &str) -> Result<Option<CaseRecord>, Error> {
        let conn = self.conn.lock().unwrap();
        let record = conn
            .query_row(
                &format!("SELECT {} FROM cases WHERE case_id = ?1", Self::CASE_COLUMNS),
                params![case_id],
                Self::case_from_row,
            )
            .optional()?;
        Ok(record)
    }

    /// An already-open case against the same accused for the same
    /// class. Further reports join it rather than opening a second one:
    /// per-opened-case pricing is forbidden precisely because opening
    /// cases is not free to the accused (a mark is set), so opening
    /// duplicates would be a way to punish without deciding.
    pub fn open_case_for(&self, accused: &str, class_id: &str) -> Result<Option<CaseRecord>, Error> {
        let conn = self.conn.lock().unwrap();
        let record = conn
            .query_row(
                &format!(
                    "SELECT {} FROM cases WHERE accused = ?1 AND class_id = ?2 AND stage = 'open'
                     ORDER BY opened_at DESC LIMIT 1",
                    Self::CASE_COLUMNS
                ),
                params![accused, class_id],
                Self::case_from_row,
            )
            .optional()?;
        Ok(record)
    }

    /// Open cases whose decision deadline has passed — the ones the
    /// deadline worker must dismiss.
    pub fn cases_overdue(&self, now: &str) -> Result<Vec<CaseRecord>, Error> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(&format!(
            "SELECT {} FROM cases WHERE stage = 'open' AND decision_deadline <= ?1",
            Self::CASE_COLUMNS
        ))?;
        let rows = statement.query_map(params![now], Self::case_from_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn append_event(&self, case_id: &str, at: &str, kind: &str, detail: &str) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO case_events (case_id, at, kind, detail) VALUES (?1, ?2, ?3, ?4)",
            params![case_id, at, kind, detail],
        )?;
        Ok(())
    }

    pub fn events(&self, case_id: &str) -> Result<Vec<(String, String, String)>, Error> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn
            .prepare("SELECT at, kind, detail FROM case_events WHERE case_id = ?1 ORDER BY sequence")?;
        let rows = statement.query_map(params![case_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    // ─── Verdicts ────────────────────────────────────────────────────

    /// Record a decision as one unit: the verdict, the case's new
    /// stage, and the event. These three were three separate writes,
    /// which meant a crash between them could leave a signed ban with
    /// no decided case — or a decided case with no verdict to justify
    /// it. Either is a record the accused cannot appeal against.
    pub fn commit_decision(&self, decision: &Decision<'_>) -> Result<(), Error> {
        let Decision {
            case,
            verdict_ref,
            disposition,
            raw,
            at,
            event_kind,
            event_detail,
            credited_reporters,
            expect_stage,
            expect_disposition,
        } = decision;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        // Move the case first, conditioned on it still being where the
        // caller found it. Nothing else in this transaction happens if
        // it has moved — no verdict is stored, no reporter is credited.
        let moved = tx.execute(
            "UPDATE cases
                SET stage = ?2, responded = ?3, disposition = ?4, appeal_deadline = ?5
              WHERE case_id = ?1
                AND stage = ?6
                AND (?7 IS NULL OR disposition IS ?7)",
            params![
                case.case_id,
                case.stage,
                case.responded as i32,
                case.disposition,
                case.appeal_deadline,
                expect_stage,
                expect_disposition,
            ],
        )?;
        if moved == 0 {
            return Err(Error::CaseState(format!(
                "case {} is no longer {expect_stage}; it was decided by someone else while this \
                 decision was being made",
                case.case_id
            )));
        }

        tx.execute(
            "INSERT OR REPLACE INTO verdicts (verdict_ref, case_id, disposition, raw, issued_at, delivered)
             VALUES (?1, ?2, ?3, ?4, ?5, COALESCE((SELECT delivered FROM verdicts WHERE verdict_ref = ?1), 0))",
            params![verdict_ref, case.case_id, disposition, raw, at],
        )?;
        tx.execute(
            "INSERT INTO case_events (case_id, at, kind, detail) VALUES (?1, ?2, ?3, ?4)",
            params![case.case_id, at, event_kind, event_detail],
        )?;
        for reporter in *credited_reporters {
            Self::credit_reporter(&tx, reporter, *disposition == "ban")?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn mark_delivered(&self, verdict_ref: &str) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE verdicts SET delivered = 1, last_error = NULL WHERE verdict_ref = ?1",
            params![verdict_ref],
        )?;
        Ok(())
    }

    /// Record a failed delivery. `refused` distinguishes the interface
    /// rejecting the verdict itself from it being unreachable, and only
    /// refusals are counted toward giving up: an interface down for
    /// three sweeps must not make the next 4xx the last straw.
    ///
    /// Returns how many refusals this verdict has now had.
    pub fn record_delivery_failure(
        &self,
        verdict_ref: &str,
        error: &str,
        refused: bool,
    ) -> Result<i64, Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE verdicts
                SET attempts = attempts + 1,
                    refusals = refusals + ?3,
                    last_error = ?2
              WHERE verdict_ref = ?1",
            params![verdict_ref, error, refused as i64],
        )?;
        let refusals = conn
            .query_row(
                "SELECT refusals FROM verdicts WHERE verdict_ref = ?1",
                params![verdict_ref],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        Ok(refusals)
    }

    /// Stop retrying a verdict the interface refuses. Not a deletion:
    /// the verdict stands, and the mark it authorizes has not moved,
    /// which is the thing an operator needs to see.
    pub fn mark_undeliverable(&self, verdict_ref: &str) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE verdicts SET undeliverable = 1 WHERE verdict_ref = ?1",
            params![verdict_ref],
        )?;
        Ok(())
    }

    /// Verdicts that have been signed, stored, and given up on. Each
    /// one is a mark that should have moved and did not — surfaced on
    /// `/health` so it reads as a fault rather than as silence.
    pub fn undeliverable_verdicts(&self) -> Result<Vec<(String, String)>, Error> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(
            "SELECT verdict_ref, COALESCE(last_error, '')
               FROM verdicts WHERE delivered = 0 AND undeliverable = 1
              ORDER BY issued_at",
        )?;
        let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Verdicts the interface has not acknowledged yet. Delivery is
    /// retried: a verdict is issued whether or not the interface is
    /// reachable, and an undelivered one is not an undecided case.
    pub fn undelivered_verdicts(&self) -> Result<Vec<UndeliveredVerdict>, Error> {
        let conn = self.conn.lock().unwrap();
        // The manifest travels with the verdict, resolved through the
        // case's mandate — the interface hashes it against what that
        // user's mandate pinned, which is not necessarily what this
        // authority publishes today.
        let mut statement = conn.prepare(
            "SELECT v.verdict_ref, v.raw, mf.raw
               FROM verdicts v
               LEFT JOIN cases c    ON c.case_id = v.case_id
               LEFT JOIN mandates m ON m.mandate_ref = c.mandate_ref
               LEFT JOIN manifests mf ON mf.manifest_hash = m.manifest_hash
              WHERE v.delivered = 0 AND v.undeliverable = 0
              ORDER BY v.issued_at",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(UndeliveredVerdict {
                verdict_ref: row.get(0)?,
                raw: row.get(1)?,
                consented_manifest: row.get(2)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reporter_weight_rises_with_upheld_reports() {
        let none = ReporterRecord::default();
        assert_eq!(none.weight(), 1.0);

        let good = ReporterRecord { upheld: 4, dismissed: 0 };
        let mixed = ReporterRecord { upheld: 2, dismissed: 2 };
        let bad = ReporterRecord { upheld: 0, dismissed: 4 };
        assert!(good.weight() > mixed.weight());
        assert!(mixed.weight() > bad.weight());
        // Even a bad record still gets heard — dismissed reports reduce
        // weight, they do not silence a reporter.
        assert!(bad.weight() > 0.0);
    }

    fn sample_case(case_id: &str) -> CaseRecord {
        CaseRecord {
            case_id: case_id.into(),
            accused: "onym:key:acc".into(),
            reporter: "onym:key:rep".into(),
            class_id: "csam".into(),
            mandate_ref: "m1".into(),
            device_binding: "d1".into(),
            stage: "decided".into(),
            opened_at: "2026-08-01T00:00:00Z".into(),
            response_deadline: "2026-08-04T00:00:00Z".into(),
            decision_deadline: "2026-08-08T00:00:00Z".into(),
            responded: false,
            disposition: None,
            appeal_deadline: None,
        }
    }

    fn decide(store: &Store, case_id: &str, disposition: &str, reporters: &[&str]) {
        let credited: Vec<String> = reporters.iter().map(|r| r.to_string()).collect();
        // The case has to exist and be open: a decision now asserts
        // that inside its own transaction rather than trusting a read
        // taken under a lock it has since released.
        let mut open = sample_case(case_id);
        open.stage = "open".into();
        store.put_case(&open).unwrap();
        store
            .commit_decision(&Decision {
                case: &sample_case(case_id),
                verdict_ref: &format!("v-{case_id}-{disposition}"),
                disposition,
                raw: b"{}",
                at: "2026-08-05T00:00:00Z",
                event_kind: "decided",
                event_detail: disposition,
                credited_reporters: &credited,
                expect_stage: "open",
                expect_disposition: None,
            })
            .unwrap();
    }

    #[test]
    fn track_record_accumulates_per_reporter() {
        let store = Store::in_memory().unwrap();
        decide(&store, "c1", "ban", &["onym:key:aa"]);
        decide(&store, "c2", "ban", &["onym:key:aa"]);
        decide(&store, "c3", "dismiss", &["onym:key:aa"]);
        decide(&store, "c4", "dismiss", &["onym:key:bb"]);

        let a = store.reporter("onym:key:aa").unwrap();
        assert_eq!((a.upheld, a.dismissed), (2, 1));
        let b = store.reporter("onym:key:bb").unwrap();
        assert_eq!((b.upheld, b.dismissed), (0, 1));
        // An unknown reporter is not an error; they simply have no
        // record yet.
        assert_eq!(store.reporter("onym:key:cc").unwrap().upheld, 0);
    }

    /// Everyone who reported the case is credited, not just whoever
    /// filed first — the case was upheld for all of them.
    #[test]
    fn every_reporter_on_a_case_is_credited() {
        let store = Store::in_memory().unwrap();
        decide(&store, "c1", "ban", &["onym:key:aa", "onym:key:bb"]);

        assert_eq!(store.reporter("onym:key:aa").unwrap().upheld, 1);
        assert_eq!(store.reporter("onym:key:bb").unwrap().upheld, 1);
    }

    /// A client-chosen report id identifies a report only within its
    /// reporter. Two reporters may pick the same one, and neither may
    /// overwrite the other's evidence record.
    #[test]
    fn a_report_id_is_scoped_to_its_reporter_and_immutable() {
        let store = Store::in_memory().unwrap();
        store
            .put_report("r1", "onym:key:aa", "onym:key:x", "csam", None, 1.0, b"first", "t0")
            .unwrap();
        // A different reporter reusing the id gets their own row.
        store
            .put_report("r1", "onym:key:bb", "onym:key:y", "csam", None, 1.0, b"second", "t0")
            .unwrap();
        assert_eq!(store.report("onym:key:aa", "r1").unwrap().unwrap().raw, b"first");
        assert_eq!(store.report("onym:key:bb", "r1").unwrap().unwrap().raw, b"second");

        // The filer cannot rewrite their own filed evidence either.
        let rewrite =
            store.put_report("r1", "onym:key:aa", "onym:key:x", "csam", None, 1.0, b"edited", "t1");
        assert!(rewrite.is_err());
        assert_eq!(store.report("onym:key:aa", "r1").unwrap().unwrap().raw, b"first");
    }

    /// A response is kept whole. A summary line is not the material the
    /// accused offered in their defence.
    #[test]
    fn responses_are_stored_whole_and_ordered() {
        let store = Store::in_memory().unwrap();
        let mut case = sample_case("c1");
        case.stage = "open".into();
        store.put_case(&case).unwrap();

        store.put_response(&case, b"{\"statement\":\"one\"}", false, "t1", "response", "one").unwrap();
        store.put_response(&case, b"{\"statement\":\"two\"}", true, "t2", "response_late", "two").unwrap();

        let stored = store.responses("c1").unwrap();
        assert_eq!(stored.len(), 2);
        assert_eq!(stored[0].0, b"{\"statement\":\"one\"}");
        assert!(!stored[0].1);
        assert!(stored[1].1, "the second response was filed late");
    }

    #[test]
    fn overdue_cases_are_found_by_deadline() {
        let store = Store::in_memory().unwrap();
        let mut case = CaseRecord {
            case_id: "c1".into(),
            accused: "onym:key:acc".into(),
            reporter: "onym:key:rep".into(),
            class_id: "csam".into(),
            mandate_ref: "m1".into(),
            device_binding: "d1".into(),
            stage: "open".into(),
            opened_at: "2026-08-01T00:00:00Z".into(),
            response_deadline: "2026-08-04T00:00:00Z".into(),
            decision_deadline: "2026-08-08T00:00:00Z".into(),
            responded: false,
            disposition: None,
            appeal_deadline: None,
        };
        store.put_case(&case).unwrap();

        assert!(store.cases_overdue("2026-08-07T00:00:00Z").unwrap().is_empty());
        assert_eq!(store.cases_overdue("2026-08-09T00:00:00Z").unwrap().len(), 1);

        // A decided case is never overdue, whatever the clock says.
        case.stage = "decided".into();
        store.put_case(&case).unwrap();
        assert!(store.cases_overdue("2026-08-09T00:00:00Z").unwrap().is_empty());
    }

    /// The upgrade path, which is the one `CREATE TABLE IF NOT EXISTS`
    /// silently does not cover. A store opened by an older build has
    /// the old `cases`, `mandates` and `verdicts` tables; adding a
    /// column to their definitions does nothing to it, and the first
    /// read that selects the new column fails. On a deployment holding
    /// live cases that means the service comes back up dead.
    #[test]
    fn an_old_store_gains_the_columns_added_since() {
        let file = std::env::temp_dir().join(format!(
            "onym-authority-migrate-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&file);

        // A store as an earlier build left it: the tables, without any
        // of the columns added since.
        {
            let conn = Connection::open(&file).unwrap();
            conn.execute_batch(
                r#"
                CREATE TABLE mandates (
                    mandate_ref    TEXT PRIMARY KEY,
                    user_key       TEXT NOT NULL,
                    device_binding TEXT NOT NULL,
                    classes        TEXT NOT NULL,
                    raw            BLOB NOT NULL,
                    accepted_at    TEXT NOT NULL
                );
                CREATE TABLE verdicts (
                    verdict_ref TEXT PRIMARY KEY,
                    case_id     TEXT NOT NULL,
                    disposition TEXT NOT NULL,
                    raw         BLOB NOT NULL,
                    issued_at   TEXT NOT NULL,
                    delivered   INTEGER NOT NULL DEFAULT 0
                );
                INSERT INTO mandates VALUES ('m1', 'onym:key:u', 'd1', 'csam', X'7b7d', 't0');
                INSERT INTO verdicts VALUES ('v1', 'c1', 'dismiss', X'7b7d', 't0', 0);
                "#,
            )
            .unwrap();
        }

        // Opening it runs the migration...
        let store = Store::open(file.to_str().unwrap()).unwrap();

        // ...and the reads that select the new columns work, on rows
        // written before those columns existed.
        let mandate = store.mandate("m1").unwrap().expect("the old mandate survives");
        assert_eq!(mandate.user_key, "onym:key:u");
        assert_eq!(mandate.manifest_hash, "", "no snapshot was kept for it, and that is the truth");
        assert_eq!(store.undelivered_verdicts().unwrap().len(), 1);
        assert!(store.undeliverable_verdicts().unwrap().is_empty());

        // Migrating twice is not an error.
        drop(store);
        let reopened = Store::open(file.to_str().unwrap()).unwrap();
        assert!(reopened.mandate("m1").unwrap().is_some());

        let _ = std::fs::remove_file(&file);
    }


    /// Two deciders racing — a moderator's `/decide` and the deadline
    /// sweep, say — must not both land. The guards read the case under
    /// one lock and the write happens under another, so without a
    /// re-assertion inside the transaction the loser would store a
    /// second signed verdict for the same case and credit its
    /// reporters twice.
    #[test]
    fn a_second_decision_on_the_same_case_is_refused() {
        let store = Store::in_memory().unwrap();
        decide(&store, "c1", "ban", &["onym:key:aa"]);

        // The second decider still holds a case it read as open.
        let stale = sample_case("c1");
        let second = store.commit_decision(&Decision {
            case: &stale,
            verdict_ref: "v-second",
            disposition: "dismiss",
            raw: b"{}",
            at: "2026-08-06T00:00:00Z",
            event_kind: "decided",
            event_detail: "dismiss",
            credited_reporters: &["onym:key:aa".to_string()],
            expect_stage: "open",
            expect_disposition: None,
        });

        assert!(matches!(second, Err(Error::CaseState(_))), "{second:?}");
        // And nothing from the losing decision survives: no verdict,
        // and no second credit.
        assert_eq!(store.undelivered_verdicts().unwrap().len(), 1);
        let reporter = store.reporter("onym:key:aa").unwrap();
        assert_eq!((reporter.upheld, reporter.dismissed), (1, 0));
    }

    /// A reversal expects to find the case decided *and* banned —
    /// reversing something that was already reversed, or dismissed, is
    /// the same race in a different direction.
    #[test]
    fn a_reversal_expects_the_ban_it_is_reversing() {
        let store = Store::in_memory().unwrap();
        decide(&store, "c1", "dismiss", &[]);

        let mut reversed = sample_case("c1");
        reversed.disposition = Some("reversed".into());
        let result = store.commit_decision(&Decision {
            case: &reversed,
            verdict_ref: "v-reversal",
            disposition: "dismiss",
            raw: b"{}",
            at: "2026-08-06T00:00:00Z",
            event_kind: "decided",
            event_detail: "reverse",
            credited_reporters: &[],
            expect_stage: "decided",
            expect_disposition: Some("ban"),
        });
        assert!(matches!(result, Err(Error::CaseState(_))), "a dismissal is not a ban to reverse");
    }

}
