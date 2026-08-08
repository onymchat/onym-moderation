//! Durable state: registered mandates, reporter track records, reports,
//! cases, and issued verdicts.

use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::Error;

pub struct Store {
    conn: Mutex<Connection>,
}

/// How many columns `CASE_COLUMNS` selects. Any query that appends its
/// own columns indexes from here, so adding a case field cannot quietly
/// shift a later read onto the wrong one — which is exactly what
/// `claim_revision` did to `cases_awaiting_assessment`.
const CASE_COLUMN_COUNT: usize = 17;

#[derive(Debug, Clone)]
/// Everything one decision writes. Grouped so that issuing a verdict,
/// moving the case, recording the event, and adjusting reporters'
/// standing cannot drift apart into separate calls that a crash could
/// interleave.
/// One filed response: the material, when it arrived, and how many the
/// case will hold. Grouped so the storage bound travels with the thing
/// it bounds rather than as a trailing argument.
/// One move of a case's claim state, and the log line that records
/// why. `expect` is the state the caller read before deciding to make
/// it — asserted by the write, because the read that justified the
/// move happened under a different lock.
pub struct CaseStateMove<'a> {
    pub case_id: &'a str,
    pub value: &'a str,
    pub expect: Option<&'a str>,
    /// The claim revision the caller rendered its page from, when it
    /// has one. `None` on the filing paths, which are not reviews.
    pub expect_claim_revision: Option<i64>,
    pub at: &'a str,
    pub event_kind: &'a str,
    pub event_detail: &'a str,
}

pub struct ResponseFiling<'a> {
    pub case: &'a CaseRecord,
    pub raw: &'a [u8],
    pub late: bool,
    pub filed_at: &'a str,
    pub event_kind: &'a str,
    pub event_detail: &'a str,
    pub limit: usize,
}

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
    /// An appeal state to move in the same transaction, when this
    /// decision *is* the answer to an appeal. Left `None` when the
    /// decision says nothing about one.
    pub appeal_state: Option<&'a str>,
    /// The case revision the decider read. Re-asserted inside the
    /// transaction: comparing the case document before signing and
    /// committing left a window in which a response could land, and
    /// the recovery path re-applied a stored decision without
    /// comparing at all. A reading of a record that has since moved
    /// must not become a verdict.
    pub expect_revision: Option<i64>,
    /// The claim revision the *reviewer* read, when this decision
    /// answers a human remedy. `expect_revision` does not cover it: a
    /// supplementary appeal filing leaves the case document a model
    /// would read untouched, so the case revision is unmoved while the
    /// file the moderator is deciding has grown. Nor does the state
    /// alone, since a supplement leaves it `pending`.
    pub expect_claim_revision: Option<i64>,
    /// Likewise for a new-holder claim, which is a separate field
    /// because it is a separate claim.
    pub new_holder_state: Option<&'a str>,
    /// One further event to record in the same transaction — the
    /// review that produced this decision. Committed here rather than
    /// appended afterwards, so the case log cannot end up describing a
    /// review whose outcome never landed, or the reverse.
    pub extra_event: Option<(&'a str, &'a str)>,
}

/// A verdict awaiting delivery, carrying the manifest bytes the case
/// was judged under. `consented_manifest` is `None` only for cases
/// whose mandate predates manifest snapshotting.
pub struct UndeliveredVerdict {
    pub verdict_ref: String,
    pub raw: Vec<u8>,
    pub consented_manifest: Option<Vec<u8>>,
    pub manifest_hash: Option<String>,
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
    /// none | pending | upheld | reversed
    pub appeal_state: String,
    /// Bumped whenever the case document changes. See the schema.
    pub revision: i64,
    /// none | pending | refused | granted. Independent of
    /// `appeal_state`: a new-holder claim is a different claim, by a
    /// different person, about a different question.
    pub new_holder_state: String,
    /// Bumped whenever either human-remedy claim changes — filed,
    /// supplemented, or decided. A review is submitted against the
    /// value it was rendered from, so a supplement or another
    /// moderator's decision arriving in between refuses the commit
    /// rather than being silently reviewed past.
    pub claim_revision: i64,
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
                appeal_deadline   TEXT,
                -- none | pending | upheld | reversed. `pending` is the
                -- moderator panel's queue: an appeal filed against a
                -- verdict and not yet reviewed by a human.
                appeal_state      TEXT NOT NULL DEFAULT 'none',
                -- Bumped by anything that changes the document a model
                -- would read: a response filed, evidence joined. An
                -- assessment records the revision it read, and a
                -- decision is conditioned on it, so a reading of a
                -- record that has since moved cannot become a verdict.
                revision          INTEGER NOT NULL DEFAULT 0,
                -- none | pending | refused | granted. Tracked
                -- separately from the appeal, because the two are
                -- different claims by different people: the accused
                -- says the verdict was wrong, a new holder says the
                -- device changed hands. Sharing one slot let a claim
                -- swallow a pending appeal — and let anyone who knows a
                -- case id file a claim and lock the accused out of
                -- appealing at all.
                new_holder_state  TEXT NOT NULL DEFAULT 'none',
                -- Bumped by anything that changes what a reviewer of a
                -- human remedy is looking at: an appeal filed or
                -- supplemented, a new-holder claim filed, either claim
                -- decided. `revision` does not cover it — a
                -- supplementary appeal filing leaves the case document
                -- a model would read untouched — so a review page
                -- rendered before the supplement would commit as
                -- though it had been read, and a reversal read from a
                -- `pending` page could still commit after another
                -- moderator had upheld the same claim.
                claim_revision    INTEGER NOT NULL DEFAULT 0
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

            -- What the classifier concluded, kept whole so an appeal
            -- reviewer sees what was decided on rather than a summary.
            CREATE TABLE IF NOT EXISTS assessments (
                case_id        TEXT PRIMARY KEY,
                raw            BLOB NOT NULL,
                recommendation TEXT NOT NULL,
                applied        INTEGER NOT NULL DEFAULT 0,
                assessed_at    TEXT NOT NULL,
                -- The exact case document the model was shown. The
                -- digest alone let the record say *that* something was
                -- judged without letting anyone see *what* — and an
                -- appeal reviewer applying the narrower canonical rule
                -- needs the material, not a hash of it.
                document       BLOB,
                -- How many times this case has been put to the model.
                -- A no-decision is retried, but not forever and not
                -- every tick: a model that cannot read a case now is
                -- unlikely to read it thirty seconds later.
                attempts       INTEGER NOT NULL DEFAULT 0
            );

            -- Moderator panel sessions. Short-lived and revocable; the
            -- panel displays disclosed evidence, so a leaked cookie is
            -- a disclosure.
            CREATE TABLE IF NOT EXISTS admin_sessions (
                token      TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
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
            // The moderator panel's appeal queue.
            ("cases", "appeal_state", "TEXT NOT NULL DEFAULT 'none'"),
            ("cases", "new_holder_state", "TEXT NOT NULL DEFAULT 'none'"),
            ("cases", "revision", "INTEGER NOT NULL DEFAULT 0"),
            ("cases", "claim_revision", "INTEGER NOT NULL DEFAULT 0"),
            ("assessments", "attempts", "INTEGER NOT NULL DEFAULT 0"),
            ("assessments", "document", "BLOB"),
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
            "INSERT OR IGNORE INTO mandates
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

    #[cfg(test)]
    pub fn remove_manifest_snapshot(&self, manifest_hash: &str) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM manifests WHERE manifest_hash = ?1",
            params![manifest_hash],
        )?;
        Ok(())
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

    #[cfg(test)]
    pub fn remove_mandate(&self, mandate_ref: &str) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM mandates WHERE mandate_ref = ?1", params![mandate_ref])?;
        Ok(())
    }

    /// Every mandate this key has registered, newest first. Standing
    /// follows any of them: a user who re-consents after a manifest is
    /// republished has not withdrawn the consent they gave under the
    /// old one, and reports already signed against it are still theirs.
    pub fn mandates_for_user(&self, user_key: &str) -> Result<Vec<MandateRecord>, Error> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(
            // `acceptedAt` is client-signed metadata, not a trustworthy
            // ordering clock. Row insertion order is the authority's
            // observation of which consent arrived last; INSERT OR
            // IGNORE above makes replay unable to refresh it.
            "SELECT mandate_ref, user_key, device_binding, classes, manifest_hash
               FROM mandates WHERE user_key = ?1 ORDER BY rowid DESC",
        )?;
        let rows = statement.query_map(params![user_key], Self::mandate_from_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn mandate_for_user(&self, user_key: &str) -> Result<Option<MandateRecord>, Error> {
        let conn = self.conn.lock().unwrap();
        let record = conn
            .query_row(
                "SELECT mandate_ref, user_key, device_binding, classes, manifest_hash
                 FROM mandates WHERE user_key = ?1 ORDER BY rowid DESC LIMIT 1",
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
    pub fn put_response(&self, filing: &ResponseFiling<'_>) -> Result<(), Error> {
        let ResponseFiling { case, raw, late, filed_at, event_kind, event_detail, limit } = filing;
        let (late, limit) = (*late, *limit);
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM responses WHERE case_id = ?1",
            params![case.case_id],
            |row| row.get(0),
        )?;
        if count >= limit as i64 {
            return Err(Error::CaseState(format!(
                "this case already holds {limit} responses; further material belongs in one of \
                 them rather than in another filing"
            )));
        }
        tx.execute(
            "INSERT INTO responses (case_id, raw, late, filed_at) VALUES (?1, ?2, ?3, ?4)",
            params![case.case_id, raw, late as i32, filed_at],
        )?;
        // Set the one flag a response actually changes, and only while
        // the case is still open. Writing the whole row back — from a
        // record read before the lock was taken — would rewrite
        // `stage`, `disposition` and `appeal_deadline` too: a response
        // landing between a decider's read and its commit would put a
        // decided case back to `open` with its disposition erased. The
        // deadline sweep would then find it overdue and dismiss it by
        // default, clearing a ban already in force and taking the
        // appeal deadline the accused was owed with it.
        let responded = tx.execute(
            "UPDATE cases SET responded = 1, revision = revision + 1
              WHERE case_id = ?1 AND stage = 'open'",
            params![case.case_id],
        )?;
        if responded == 0 {
            return Err(Error::CaseState(
                "the case was decided while this response was being filed".into(),
            ));
        }
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

    /// Test-only: record an opening verdict for a case that already
    /// exists, and mark it delivered. In the service the two happen
    /// together in `open_case_atomically` and the delivery sweep; a
    /// fixture that builds a case row directly still needs a served
    /// notice, because a ban now requires one.
    #[cfg(test)]
    pub fn put_delivered_open_case_verdict(
        &self,
        case_id: &str,
        verdict_ref: &str,
    ) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO verdicts
             (verdict_ref, case_id, disposition, raw, issued_at, delivered)
             VALUES (?1, ?2, 'open-case', ?3, '2026-08-01T00:00:00Z', 1)",
            params![verdict_ref, case_id, b"{}".as_slice()],
        )?;
        Ok(())
    }


    /// Test-only, and deliberately so. In the service every case-row
    /// change is a conditional `UPDATE` of the columns that change:
    /// writing a whole row back from a record read before the lock is
    /// how a response reopened a decided case.
    #[cfg(test)]
    fn write_case(conn: &rusqlite::Connection, case: &CaseRecord) -> Result<(), Error> {
        conn.execute(
            "INSERT OR REPLACE INTO cases
             (case_id, accused, reporter, class_id, mandate_ref, device_binding, stage,
              opened_at, response_deadline, decision_deadline, responded, disposition,
              appeal_deadline, appeal_state, new_holder_state, claim_revision)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
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
                case.appeal_state,
                case.new_holder_state,
                case.claim_revision,
            ],
        )?;
        Ok(())
    }

    /// Move a case's appeal state and log why, in one write. This is
    /// the one case-row change that is not itself a decision: an appeal
    /// arriving or being reviewed changes what the panel shows without
    /// issuing a verdict. A reversal still goes through
    /// `commit_decision`; this only records the appeal's own progress.
    /// Move a new-holder claim's state. Separate from the appeal's,
    /// so neither can overwrite the other: they are different claims,
    /// by different people, about different questions.
    #[allow(clippy::too_many_arguments)]
    pub fn set_new_holder_state(
        &self,
        case_id: &str,
        value: &str,
        expect: Option<&str>,
        expect_claim_revision: Option<i64>,
        at: &str,
        event_kind: &str,
        event_detail: &str,
    ) -> Result<(), Error> {
        self.set_case_field(
            "new_holder_state",
            CaseStateMove {
                case_id,
                value,
                expect,
                expect_claim_revision,
                at,
                event_kind,
                event_detail,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn set_appeal_state(
        &self,
        case_id: &str,
        appeal_state: &str,
        expect: Option<&str>,
        expect_claim_revision: Option<i64>,
        at: &str,
        event_kind: &str,
        event_detail: &str,
    ) -> Result<(), Error> {
        self.set_case_field(
            "appeal_state",
            CaseStateMove {
                case_id,
                value: appeal_state,
                expect,
                expect_claim_revision,
                at,
                event_kind,
                event_detail,
            },
        )
    }

    /// Note new material on a claim that does not move its state: a
    /// supplementary appeal filing. Bounded like any case event, and it
    /// moves `claim_revision`, because a review rendered before it read
    /// a shorter file than the one it is about to decide.
    pub fn append_claim_event_bounded(
        &self,
        case_id: &str,
        at: &str,
        kind: &str,
        detail: &str,
        limit: usize,
    ) -> Result<bool, Error> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM case_events WHERE case_id = ?1 AND kind = ?2",
            params![case_id, kind],
            |row| row.get(0),
        )?;
        if count >= limit as i64 {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO case_events (case_id, at, kind, detail) VALUES (?1, ?2, ?3, ?4)",
            params![case_id, at, kind, detail],
        )?;
        tx.execute(
            "UPDATE cases SET claim_revision = claim_revision + 1 WHERE case_id = ?1",
            params![case_id],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// `expect` is the state the caller read before deciding to make
    /// this move. The read and the write are separate lock
    /// acquisitions, so without it two moderators could both pass the
    /// "is it pending?" check and both record a review of the same
    /// claim — and, on the filing path, concurrent appeals could each
    /// take the unbounded first-filing arm.
    ///
    /// `expect_claim_revision` is the rest of that answer. The state
    /// alone does not distinguish a claim that gained a supplementary
    /// filing while the reviewer read the page, because a supplement
    /// leaves it `pending`; the revision does.
    fn set_case_field(&self, column: &str, move_: CaseStateMove<'_>) -> Result<(), Error> {
        let CaseStateMove {
            case_id,
            value,
            expect,
            expect_claim_revision,
            at,
            event_kind,
            event_detail,
        } = move_;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let changed = tx.execute(
            &format!(
                "UPDATE cases SET {column} = ?2, claim_revision = claim_revision + 1
                  WHERE case_id = ?1
                    AND (?3 IS NULL OR {column} = ?3)
                    AND (?4 IS NULL OR claim_revision = ?4)"
            ),
            params![case_id, value, expect, expect_claim_revision],
        )?;
        if changed == 0 {
            return Err(Error::CaseState(format!(
                "case {case_id} is not in the state this change was decided against; someone \
                 else moved it first, or the claim gained material this review did not read"
            )));
        }
        tx.execute(
            "INSERT INTO case_events (case_id, at, kind, detail) VALUES (?1, ?2, ?3, ?4)",
            params![case_id, at, event_kind, event_detail],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Test-only. In the service a case row moves only inside a
    /// transaction that also writes the verdict justifying the move —
    /// see `open_case_atomically`, `commit_decision`, and
    /// `set_appeal_state`.
    #[cfg(test)]
    pub fn put_case(&self, case: &CaseRecord) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        Self::write_case(&conn, case)
    }

    /// Open a case, attach its opening report, and issue its interim
    /// verdict as one unit. A deliverable verdict must never name a
    /// case whose evidence is not attached yet.
    ///
    /// Returns `Ok(false)` when another case is already open for this
    /// accused and class — the unique index caught a concurrent
    /// opener, and the caller should join that case instead of opening
    /// a second one.
    #[allow(clippy::too_many_arguments)]
    pub fn open_case_atomically(
        &self,
        case: &CaseRecord,
        opening_reporter: &str,
        opening_report_id: &str,
        verdict_ref: &str,
        disposition: &str,
        raw: &[u8],
        at: &str,
        event_detail: &str,
        evidence_summary: &str,
    ) -> Result<bool, Error> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        // Plain INSERT, not INSERT OR REPLACE: the unique partial index
        // is the point, and swallowing its violation would defeat it.
        match tx.execute(
            "INSERT INTO cases
             (case_id, accused, reporter, class_id, mandate_ref, device_binding, stage,
              opened_at, response_deadline, decision_deadline, responded, disposition,
              appeal_deadline, appeal_state, new_holder_state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
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
                case.appeal_state,
                case.new_holder_state,
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
        let attached = tx.execute(
            "UPDATE reports SET case_id = ?3
             WHERE reporter = ?1 AND report_id = ?2 AND case_id IS NULL",
            params![opening_reporter, opening_report_id, case.case_id],
        )?;
        if attached != 1 {
            return Err(Error::Internal(format!(
                "opening report {opening_report_id:?} was not available to attach to case {:?}",
                case.case_id
            )));
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
        // What this notice put before the accused, so a later join
        // carrying the same material can be recognised as alleging
        // nothing new.
        tx.execute(
            "INSERT INTO case_events (case_id, at, kind, detail) VALUES (?1, ?2, ?3, ?4)",
            params![case.case_id, at, "notice_evidence", evidence_summary],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Attach newly joined evidence, restart the case windows, and
    /// enqueue the revised signed notice as one transaction. A joined
    /// report must never become adjudicable before its notice does.
    #[allow(clippy::too_many_arguments)]
    pub fn renotice_case_atomically(
        &self,
        case: &CaseRecord,
        reporter: &str,
        report_id: &str,
        verdict_ref: &str,
        disposition: &str,
        raw: &[u8],
        at: &str,
        event_detail: &str,
        evidence_summary: &str,
        max_notices: i64,
    ) -> Result<bool, Error> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        // Re-assert dedupe and the cap under the same lock that
        // attaches evidence. Concurrent joins may all have observed
        // the previous count.
        let notices: i64 = tx.query_row(
            "SELECT COUNT(*) FROM case_events
              WHERE case_id = ?1 AND kind = 'notice_evidence'",
            params![case.case_id],
            |row| row.get(0),
        )?;
        let already_noticed: i64 = tx.query_row(
            "SELECT COUNT(*) FROM case_events
              WHERE case_id = ?1 AND kind = 'notice_evidence' AND detail = ?2",
            params![case.case_id, evidence_summary],
            |row| row.get(0),
        )?;
        if notices >= max_notices || already_noticed > 0 {
            return Ok(false);
        }
        // `decision_deadline > ?4` is the point. A report arriving
        // after the deadline but before the sweep ran would otherwise
        // move the horizon forward on a case the contract had already
        // ended in the accused's favour — the same "undecided is
        // dismissal" race the deciders were fixed for, reached through
        // intake instead.
        let revised = tx.execute(
            "UPDATE cases
                SET response_deadline = ?2, decision_deadline = ?3, revision = revision + 1
              WHERE case_id = ?1 AND stage = 'open' AND decision_deadline > ?4",
            params![case.case_id, case.response_deadline, case.decision_deadline, at],
        )?;
        if revised == 0 {
            return Ok(false);
        }
        let attached = tx.execute(
            "UPDATE reports SET case_id = ?3
             WHERE reporter = ?1 AND report_id = ?2 AND case_id IS NULL",
            params![reporter, report_id, case.case_id],
        )?;
        if attached != 1 {
            return Err(Error::Internal(format!(
                "joined report {report_id:?} was not available to attach to case {:?}",
                case.case_id
            )));
        }
        tx.execute(
            "INSERT OR IGNORE INTO verdicts
             (verdict_ref, case_id, disposition, raw, issued_at, delivered)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            params![verdict_ref, case.case_id, disposition, raw, at],
        )?;
        tx.execute(
            "INSERT INTO case_events (case_id, at, kind, detail) VALUES (?1, ?2, ?3, ?4)",
            params![case.case_id, at, "report_joined", event_detail],
        )?;
        // What this revised notice put before the accused.
        tx.execute(
            "INSERT INTO case_events (case_id, at, kind, detail) VALUES (?1, ?2, ?3, ?4)",
            params![case.case_id, at, "notice_evidence", evidence_summary],
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
            appeal_state: row.get(13)?,
            new_holder_state: row.get(14)?,
            revision: row.get(15)?,
            claim_revision: row.get(CASE_COLUMN_COUNT - 1)?,
        })
    }

    const CASE_COLUMNS: &'static str = "case_id, accused, reporter, class_id, mandate_ref, \
         device_binding, stage, opened_at, response_deadline, decision_deadline, responded, \
         disposition, appeal_deadline, appeal_state, new_holder_state, revision, claim_revision";

    /// The same list, qualified — `assessments` also has a `case_id`,
    /// so an unqualified join is ambiguous.
    const CASE_COLUMNS_C: &'static str = "c.case_id, c.accused, c.reporter, c.class_id, \
         c.mandate_ref, c.device_binding, c.stage, c.opened_at, c.response_deadline, \
         c.decision_deadline, c.responded, c.disposition, c.appeal_deadline, c.appeal_state, \
         c.new_holder_state, c.revision, c.claim_revision";

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

    /// Append an event only while fewer than `limit` events of this
    /// kind exist for the case. The count and insert share the store
    /// lock, so concurrent requests cannot all observe the same free
    /// slot and overflow the bound.
    /// Record a new-holder claim: bound it, log it, and queue the case
    /// for a human — all under one lock.
    ///
    /// Two findings meet here. The endpoint is unauthenticated, so a
    /// count followed by a separate write lets a concurrent burst
    /// overrun the cap. And the claim must be queued under its *own*
    /// state: writing the appeal's would swallow a pending appeal, and
    /// since anyone knowing a case id can file a claim, it would also
    /// let a stranger lock the accused out of appealing at all.
    ///
    /// A claim filed while one is already queued is logged against the
    /// queued case rather than re-queueing it, so a reviewer sees all
    /// of them without the queue flapping. A claim filed after one was
    /// *refused* does re-queue: the endpoint is unauthenticated, so a
    /// stranger filing first and a moderator refusing it would
    /// otherwise consume the genuine holder's §5.7 remedy permanently
    /// — the same failure moving off the shared `appeal_state` field
    /// was meant to close. `MAX_NEW_HOLDER_CLAIMS` still bounds it, so
    /// re-queueing is not an unbounded way to demand review.
    ///
    /// `granted` does not re-queue: the marks are already cleared, so
    /// there is no remedy left to ask for.
    pub fn record_new_holder_claim(
        &self,
        case_id: &str,
        at: &str,
        detail: &str,
        limit: usize,
    ) -> Result<bool, Error> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM case_events WHERE case_id = ?1 AND kind = 'new_holder_claim'",
            params![case_id],
            |row| row.get(0),
        )?;
        if count >= limit as i64 {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO case_events (case_id, at, kind, detail)
             VALUES (?1, ?2, 'new_holder_claim', ?3)",
            params![case_id, at, detail],
        )?;
        // The claim revision moves for *every* claim, including one
        // filed against an already-queued case: it is material a
        // reviewer has not seen, and a review submitted from a page
        // rendered before it must not commit as though it had been.
        tx.execute(
            "UPDATE cases
                SET new_holder_state = CASE
                        WHEN new_holder_state IN ('none', 'refused') THEN 'pending'
                        ELSE new_holder_state
                    END,
                    claim_revision = claim_revision + 1
              WHERE case_id = ?1",
            params![case_id],
        )?;
        tx.commit()?;
        Ok(true)
    }


    pub fn append_event_bounded(
        &self,
        case_id: &str,
        at: &str,
        kind: &str,
        detail: &str,
        limit: usize,
    ) -> Result<bool, Error> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM case_events WHERE case_id = ?1 AND kind = ?2",
            params![case_id, kind],
            |row| row.get(0),
        )?;
        if count >= limit as i64 {
            return Ok(false);
        }
        conn.execute(
            "INSERT INTO case_events (case_id, at, kind, detail) VALUES (?1, ?2, ?3, ?4)",
            params![case_id, at, kind, detail],
        )?;
        Ok(true)
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

    /// The disclosed content of every report joined to a case — what
    /// the classifier reads and what a reviewer is shown.
    pub fn evidence_for_case(&self, case_id: &str) -> Result<Vec<String>, Error> {
        let conn = self.conn.lock().unwrap();
        // `report_id` breaks ties: two reports filed in the same second
        // would otherwise order arbitrarily between reads, changing the
        // document's digest with nothing in the case having changed —
        // which reads as "the record moved while the model was reading
        // it" and discards a perfectly good assessment.
        let mut statement = conn
            .prepare("SELECT raw FROM reports WHERE case_id = ?1 ORDER BY filed_at, report_id")?;
        let rows = statement.query_map(params![case_id], |row| row.get::<_, Vec<u8>>(0))?;

        let mut out = Vec::new();
        for row in rows {
            let raw = row?;
            let Ok(report) = serde_json::from_slice::<serde_json::Value>(&raw) else {
                continue;
            };
            let Some(items) = report.get("evidence").and_then(|e| e.as_array()) else {
                continue;
            };
            for item in items {
                if let Some(content) = item.get("disclosedContent").and_then(|c| c.as_str()) {
                    out.push(content.to_string());
                }
            }
        }
        Ok(out)
    }

    /// Cases with an appeal awaiting human review — the moderator
    /// panel's queue.
    pub fn cases_awaiting_appeal_review(&self) -> Result<Vec<CaseRecord>, Error> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(&format!(
            "SELECT {} FROM cases
              WHERE appeal_state = 'pending' OR new_holder_state = 'pending'
              ORDER BY opened_at",
            Self::CASE_COLUMNS
        ))?;
        let rows = statement.query_map([], Self::case_from_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn recent_cases(&self, limit: i64) -> Result<Vec<CaseRecord>, Error> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(&format!(
            "SELECT {} FROM cases ORDER BY opened_at DESC LIMIT ?1",
            Self::CASE_COLUMNS
        ))?;
        let rows = statement.query_map(params![limit], Self::case_from_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Open cases with no assessment yet — retried by the sweep, since
    /// a classifier outage must not strand a case.
    /// The reporters' own explanations attached to evidence items —
    /// untrusted text, and labelled as such by the caller. Kept
    /// separate from the material itself because they are an assertion
    /// *about* the evidence rather than evidence of authorship.
    pub fn report_context_for_case(&self, case_id: &str) -> Result<Vec<String>, Error> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn
            .prepare("SELECT raw FROM reports WHERE case_id = ?1 ORDER BY filed_at, report_id")?;
        let rows = statement.query_map(params![case_id], |row| row.get::<_, Vec<u8>>(0))?;

        let mut out = Vec::new();
        for row in rows {
            let raw = row?;
            let Ok(report) = serde_json::from_slice::<serde_json::Value>(&raw) else {
                continue;
            };
            let Some(items) = report.get("evidence").and_then(|e| e.as_array()) else {
                continue;
            };
            for item in items {
                if let Some(context) = item.get("context").and_then(|c| c.as_str()) {
                    if !context.trim().is_empty() {
                        out.push(context.to_string());
                    }
                }
            }
        }
        Ok(out)
    }

    /// Open cases ready for automated assessment: the accused's
    /// response window has closed, and either nothing has assessed them
    /// yet or the last attempt reached no decision.
    ///
    /// The window condition is policy, not scheduling — §4.1 has the
    /// authority assess the *completed* case document. Retrying a
    /// no-decision is the "valid retry" §4.2 allows: a model that
    /// returned garbage once may answer on the next pass, and if it
    /// never does, the decision deadline dismisses the case.
    /// Each case comes back with how many times it has already been
    /// put to the model, and when it last was, so the caller can space
    /// retries out instead of hammering an unhealthy model every tick.
    /// Open cases carrying a decision the model reached but that was
    /// never applied.
    ///
    /// A guard can refuse an automated decision for a reason that later
    /// stops being true — most obviously `require_notice_delivered`,
    /// which refuses while the opening verdict is still queued for the
    /// interface. Without a path back, that refusal was permanent: the
    /// assessment row kept its `ban`, nothing re-attempted it, and the
    /// case ran to its decision deadline and dismissed. In autonomous
    /// mode no human would ever have seen it, because no ban means no
    /// appeal means nothing in the panel's queue.
    pub fn cases_with_unapplied_decision(&self) -> Result<Vec<CaseRecord>, Error> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(&format!(
            "SELECT {} FROM cases c
               JOIN assessments a ON a.case_id = c.case_id
              WHERE c.stage = 'open'
                AND a.applied = 0
                AND a.recommendation IN ('ban', 'dismiss')
              ORDER BY c.opened_at",
            Self::CASE_COLUMNS_C
        ))?;
        let rows = statement.query_map([], Self::case_from_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn cases_awaiting_assessment(
        &self,
        now: &str,
    ) -> Result<Vec<(CaseRecord, i64, Option<String>)>, Error> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(&format!(
            "SELECT {}, COALESCE(a.attempts, 0), a.assessed_at
               FROM cases c
               LEFT JOIN assessments a ON a.case_id = c.case_id
              WHERE c.stage = 'open'
                AND c.response_deadline <= ?1
                AND (a.case_id IS NULL OR a.recommendation = 'no-decision')
              ORDER BY c.opened_at",
            Self::CASE_COLUMNS_C
        ))?;
        let rows = statement.query_map(params![now], |row| {
            // Indexed past the case columns, so adding one to
            // `CASE_COLUMNS_C` does not silently start reading a case
            // field as an attempt count.
            Ok((Self::case_from_row(row)?, row.get(CASE_COLUMN_COUNT)?, row.get(CASE_COLUMN_COUNT + 1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Store an assessment. `counted` is false for a reading that was
    /// discarded through no fault of the model or the case — the
    /// attempt budget exists to stop hammering an unhealthy model, and
    /// spending it on something neither of them did wrong turns a
    /// safeguard into a way to run a case out the clock.
    pub fn put_assessment(
        &self,
        case_id: &str,
        raw: &[u8],
        recommendation: &str,
        document: &str,
        counted: bool,
    ) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO assessments
             (case_id, raw, recommendation, applied, assessed_at, attempts, document)
             VALUES (?1, ?2, ?3,
                     COALESCE((SELECT applied FROM assessments WHERE case_id = ?1), 0),
                     ?4,
                     COALESCE((SELECT attempts FROM assessments WHERE case_id = ?1), 0) + ?6,
                     ?5)",
            params![case_id, raw, recommendation, crate::util::format_timestamp(
                time::OffsetDateTime::now_utc()
            ), document, counted as i64],
        )?;
        Ok(())
    }

    /// Discard a stored decision so the sweep reassesses the case as
    /// it now stands. Not a deletion: the reading stays on file as a
    /// no-decision, with its attempt already counted, so the record
    /// still says a model looked and what it saw.
    pub fn invalidate_assessment(&self, case_id: &str) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE assessments SET recommendation = 'no-decision' WHERE case_id = ?1",
            params![case_id],
        )?;
        Ok(())
    }

    /// The exact document the model was shown for this case, if one is
    /// on file. What an appeal is actually about.
    pub fn assessed_document(&self, case_id: &str) -> Result<Option<String>, Error> {
        let conn = self.conn.lock().unwrap();
        let raw = conn
            .query_row(
                "SELECT document FROM assessments WHERE case_id = ?1",
                params![case_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        Ok(raw)
    }

    /// The stored assessment and whether it has been acted on.
    pub fn assessment(&self, case_id: &str) -> Result<Option<(Vec<u8>, bool)>, Error> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT raw, applied FROM assessments WHERE case_id = ?1",
                params![case_id],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i32>(1)? != 0)),
            )
            .optional()?;
        Ok(row)
    }

    pub fn mark_assessment_applied(&self, case_id: &str) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE assessments SET applied = 1 WHERE case_id = ?1",
            params![case_id],
        )?;
        Ok(())
    }

    // ─── Admin sessions ──────────────────────────────────────────────

    pub fn create_admin_session(&self, token: &str, now: &str, expires_at: &str) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM admin_sessions WHERE expires_at < ?1", params![now])?;
        conn.execute(
            "INSERT OR REPLACE INTO admin_sessions (token, created_at, expires_at) VALUES (?1, ?2, ?3)",
            params![token, now, expires_at],
        )?;
        Ok(())
    }

    pub fn admin_session_valid(&self, token: &str, now: &str) -> Result<bool, Error> {
        let conn = self.conn.lock().unwrap();
        let valid: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM admin_sessions WHERE token = ?1 AND expires_at > ?2",
                params![token, now],
                |row| row.get(0),
            )
            .optional()?;
        Ok(valid.is_some())
    }

    pub fn destroy_admin_session(&self, token: &str) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM admin_sessions WHERE token = ?1", params![token])?;
        Ok(())
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
            expect_revision,
            expect_claim_revision,
            appeal_state,
            new_holder_state,
            extra_event,
        } = decision;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        // Move the case first, conditioned on it still being where the
        // caller found it. Nothing else in this transaction happens if
        // it has moved — no verdict is stored, no reporter is credited.
        // `responded` is deliberately absent: a decision does not change
        // it, and writing it back from a read taken before the lock
        // would erase a response that arrived in between — the record
        // would then say the accused never answered.
        let moved = tx.execute(
            "UPDATE cases
                SET stage = ?2, disposition = ?3, appeal_deadline = ?4
              WHERE case_id = ?1
                AND stage = ?5
                AND (?6 IS NULL OR disposition IS ?6)
                AND (?7 IS NULL OR revision = ?7)
                AND (?8 IS NULL OR claim_revision = ?8)",
            params![
                case.case_id,
                case.stage,
                case.disposition,
                case.appeal_deadline,
                expect_stage,
                expect_disposition,
                expect_revision,
                expect_claim_revision,
            ],
        )?;
        if moved == 0 {
            return Err(Error::CaseState(format!(
                "case {} is no longer {expect_stage} at the revision this decision was made \
                 against; it was decided, its record changed, or the claim under review gained \
                 material this review did not read, while the decision was being made",
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
        // Same transaction: a reversal that committed while its appeal
        // stayed `pending` would leave the case reversed and still in
        // the panel's queue, with the review it answers unrecorded.
        // Each claim move takes the claim revision with it, so a second
        // reviewer holding a page rendered before this one commits is
        // refused rather than deciding a claim that has been answered.
        if let Some(appeal_state) = appeal_state {
            tx.execute(
                "UPDATE cases SET appeal_state = ?2, claim_revision = claim_revision + 1
                  WHERE case_id = ?1",
                params![case.case_id, appeal_state],
            )?;
        }
        if let Some(new_holder_state) = new_holder_state {
            tx.execute(
                "UPDATE cases SET new_holder_state = ?2, claim_revision = claim_revision + 1
                  WHERE case_id = ?1",
                params![case.case_id, new_holder_state],
            )?;
        }
        if let Some((kind, detail)) = extra_event {
            tx.execute(
                "INSERT INTO case_events (case_id, at, kind, detail) VALUES (?1, ?2, ?3, ?4)",
                params![case.case_id, at, kind, detail],
            )?;
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

    /// Whether the interface acknowledged the interim verdict that
    /// carries this case's notice. A sanction cannot rely on a response
    /// window the accused's interface never learned existed.
    /// How many notices this case has issued, and whether any of them
    /// already covers this exact evidence.
    ///
    /// The same accused-signed material, re-filed under a fresh report
    /// id, produced a fresh notice and restarted the windows — so a
    /// reporter could hold a case open, and its mark on, indefinitely
    /// without ever alleging anything new.
    pub fn notice_status(&self, case_id: &str, evidence_summary: &str) -> Result<(i64, bool), Error> {
        let conn = self.conn.lock().unwrap();
        let notices: i64 = conn.query_row(
            "SELECT COUNT(*) FROM case_events WHERE case_id = ?1 AND kind = 'notice_evidence'",
            params![case_id],
            |row| row.get(0),
        )?;
        let seen: i64 = conn.query_row(
            "SELECT COUNT(*) FROM case_events
              WHERE case_id = ?1 AND kind = 'notice_evidence' AND detail = ?2",
            params![case_id, evidence_summary],
            |row| row.get(0),
        )?;
        Ok((notices, seen > 0))
    }

    /// Attach without re-noticing only while the case remains open and
    /// an existing notice covers these exact evidence bytes.
    pub fn attach_noticed_report(
        &self,
        reporter: &str,
        report_id: &str,
        case_id: &str,
        at: &str,
        evidence_summary: &str,
        detail: &str,
    ) -> Result<bool, Error> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let eligible: i64 = tx.query_row(
            "SELECT COUNT(*) FROM cases c
              WHERE c.case_id = ?1
                AND c.stage = 'open'
                AND c.decision_deadline > ?2
                AND EXISTS (
                    SELECT 1 FROM case_events e
                     WHERE e.case_id = c.case_id
                       AND e.kind = 'notice_evidence'
                       AND e.detail = ?3
                )",
            params![case_id, at, evidence_summary],
            |row| row.get(0),
        )?;
        if eligible == 0 {
            return Ok(false);
        }
        let attached = tx.execute(
            "UPDATE reports SET case_id = ?3
             WHERE reporter = ?1 AND report_id = ?2 AND case_id IS NULL",
            params![reporter, report_id, case_id],
        )?;
        if attached != 1 {
            return Err(Error::Internal(format!(
                "joined report {report_id:?} was not available to attach to case {case_id:?}"
            )));
        }
        // The document a model reads is built from the case's reports,
        // and it does not dedupe — so even a report whose evidence is
        // already noticed adds to it. Without this bump the schema's
        // own promise ("bumped by … evidence joined") was false, the
        // in-flight digest check and the revision check disagreed, and
        // the recovery path would apply a stored decision taken from a
        // reading of a document that had since changed.
        tx.execute(
            "UPDATE cases SET revision = revision + 1 WHERE case_id = ?1",
            params![case_id],
        )?;
        tx.execute(
            "INSERT INTO case_events (case_id, at, kind, detail) VALUES (?1, ?2, ?3, ?4)",
            params![case_id, at, "report_joined", detail],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Test-only: put every one of a case's notices back in the queue.
    #[cfg(test)]
    pub fn undeliver_open_case_verdicts(&self, case_id: &str) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE verdicts SET delivered = 0 WHERE case_id = ?1 AND disposition = 'open-case'",
            params![case_id],
        )?;
        Ok(())
    }

    /// Whether **every** notice this case has issued has reached the
    /// interface.
    ///
    /// Not just the latest. Each joined report emits its own
    /// `open-case` verdict whose reasoning hashes only that report's
    /// evidence, so checking the newest one let an undelivered earlier
    /// notice's allegations sit in the case — attached, credited, and
    /// available to support a ban — while the accused had never been
    /// served with them. Two joins were enough to recreate exactly the
    /// notice-free evidence this guard exists to prevent.
    ///
    /// A case with no notice at all answers `false`: there is nothing
    /// to have been served.
    pub fn open_case_verdict_delivered(&self, case_id: &str) -> Result<bool, Error> {
        let conn = self.conn.lock().unwrap();
        let (total, delivered): (i64, i64) = conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(delivered), 0) FROM verdicts
              WHERE case_id = ?1 AND disposition = 'open-case'",
            params![case_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(total > 0 && total == delivered)
    }

    /// The case's notices that have not reached the interface, and
    /// whether each has been given up on.
    ///
    /// `open_case_verdict_delivered` answers yes-or-no, which is the
    /// right guard and a useless diagnosis. A notice the interface
    /// refuses on shape is marked `undeliverable` and keeps
    /// `delivered = 0` forever, so the guard refuses every ban on that
    /// case for the rest of its life while the error said only that
    /// "the opening verdict has not reached the interface" — true, and
    /// no help at all in finding the one ref that is stuck or knowing
    /// that `/v1/verdicts/:ref/requeue` is the way out.
    pub fn undelivered_case_notices(
        &self,
        case_id: &str,
    ) -> Result<Vec<(String, bool)>, Error> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(
            "SELECT verdict_ref, undeliverable FROM verdicts
              WHERE case_id = ?1 AND disposition = 'open-case' AND delivered = 0
              ORDER BY issued_at, verdict_ref",
        )?;
        let rows = statement
            .query_map(params![case_id], |row| Ok((row.get(0)?, row.get::<_, i32>(1)? != 0)))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
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

    /// Requeue a verdict after an operator repairs the interface,
    /// credentials, or cross-check that caused a permanent refusal.
    /// Historical attempt count is preserved; the fresh refusal budget
    /// starts at zero.
    pub fn requeue_verdict(&self, verdict_ref: &str) -> Result<bool, Error> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE verdicts
                SET undeliverable = 0, refusals = 0, last_error = NULL
              WHERE verdict_ref = ?1 AND delivered = 0 AND undeliverable = 1",
            params![verdict_ref],
        )?;
        Ok(changed == 1)
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
            "SELECT v.verdict_ref, v.raw, mf.raw, m.manifest_hash
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
                manifest_hash: row.get(3)?,
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
            appeal_state: "none".into(),
            new_holder_state: "none".into(),
            revision: 0,
            claim_revision: 0,
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
                expect_revision: None,
                expect_claim_revision: None,
                appeal_state: None,
                new_holder_state: None,
                extra_event: None,
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

        store
            .put_response(&ResponseFiling {
                case: &case,
                raw: b"{\"statement\":\"one\"}",
                late: false,
                filed_at: "t1",
                event_kind: "response",
                event_detail: "one",
                limit: 2,
            })
            .unwrap();
        store
            .put_response(&ResponseFiling {
                case: &case,
                raw: b"{\"statement\":\"two\"}",
                late: true,
                filed_at: "t2",
                event_kind: "response_late",
                event_detail: "two",
                limit: 2,
            })
            .unwrap();
        assert!(
            store
                .put_response(&ResponseFiling {
                    case: &case,
                    raw: b"{\"statement\":\"three\"}",
                    late: false,
                    filed_at: "t3",
                    event_kind: "response",
                    event_detail: "three",
                    limit: 2,
                })
                .is_err(),
            "the count and insert enforce the bound under one store lock"
        );

        let stored = store.responses("c1").unwrap();
        assert_eq!(stored.len(), 2);
        assert_eq!(stored[0].0, b"{\"statement\":\"one\"}");
        assert!(!stored[0].1);
        assert!(stored[1].1, "the second response was filed late");
    }

    #[test]
    fn bounded_events_hold_their_cap_under_concurrency() {
        let store = std::sync::Arc::new(Store::in_memory().unwrap());
        store.put_case(&sample_case("c1")).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(32));
        let mut workers = Vec::new();
        for index in 0..32 {
            let store = std::sync::Arc::clone(&store);
            let barrier = std::sync::Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                store
                    .append_event_bounded(
                        "c1",
                        "t1",
                        "new_holder_claim",
                        &format!("claim {index}"),
                        8,
                    )
                    .unwrap()
            }));
        }
        let inserted = workers
            .into_iter()
            .map(|worker| worker.join().unwrap() as usize)
            .sum::<usize>();
        assert_eq!(inserted, 8);
        assert_eq!(
            store
                .events("c1")
                .unwrap()
                .iter()
                .filter(|(_, kind, _)| kind == "new_holder_claim")
                .count(),
            8
        );
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
            appeal_state: "none".into(),
            new_holder_state: "none".into(),
            revision: 0,
            claim_revision: 0,
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
                CREATE TABLE cases (
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
                INSERT INTO mandates VALUES ('m1', 'onym:key:u', 'd1', 'csam', X'7b7d', 't0');
                INSERT INTO verdicts VALUES ('v1', 'c1', 'dismiss', X'7b7d', 't0', 0);
                INSERT INTO cases VALUES ('c1', 'onym:key:a', 'onym:key:r', 'csam', 'm1', 'd1',
                                          'open', 't0', 't1', 't2', 0, NULL, NULL);
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

        // The case read is the one that would have taken the service
        // down: `CASE_COLUMNS` selects `appeal_state`, which an old
        // `cases` table does not have.
        let case = store.case("c1").unwrap().expect("the old case survives");
        assert_eq!(case.stage, "open");
        assert_eq!(case.appeal_state, "none", "an old case has never been appealed");
        assert_eq!(store.cases_overdue("t9").unwrap().len(), 1);

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
            expect_revision: None,
            expect_claim_revision: None,
            appeal_state: None,
            new_holder_state: None,
            extra_event: None,
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
            expect_revision: None,
            expect_claim_revision: None,
            appeal_state: None,
            new_holder_state: None,
            extra_event: None,
        });
        assert!(matches!(result, Err(Error::CaseState(_))), "a dismissal is not a ban to reverse");
    }


    /// The handler reads the case, decides the claim is pending, and
    /// then writes — two lock acquisitions. Two moderators can both
    /// pass that read, so the write itself has to assert the state it
    /// was decided against.
    #[test]
    fn a_state_move_is_refused_when_the_state_already_moved() {
        let store = Store::in_memory().unwrap();
        let mut case = sample_case("c1");
        case.appeal_state = "pending".into();
        store.put_case(&case).unwrap();

        store
            .set_appeal_state("c1", "upheld", Some("pending"), None, "t1", "appeal_upheld", "hash:a")
            .unwrap();

        // A second reviewer, holding the same read.
        let second =
            store.set_appeal_state("c1", "reversed", Some("pending"), None, "t2", "appeal_reversed", "hash:b");
        assert!(matches!(second, Err(Error::CaseState(_))), "{second:?}");

        assert_eq!(store.case("c1").unwrap().unwrap().appeal_state, "upheld");
        assert_eq!(
            store
                .events("c1")
                .unwrap()
                .iter()
                .filter(|(_, kind, _)| kind.starts_with("appeal_"))
                .count(),
            1,
            "one review, one record — the losing one leaves no trace"
        );
    }

    /// `CASE_COLUMNS` is selected by two queries that then append their
    /// own columns and read them by index. Adding a case field without
    /// moving those indexes silently reads a case field as an attempt
    /// count — which is what `claim_revision` did until this pinned it.
    #[test]
    fn the_case_column_count_matches_the_column_list() {
        assert_eq!(Store::CASE_COLUMNS.split(',').count(), CASE_COLUMN_COUNT);
        assert_eq!(Store::CASE_COLUMNS_C.split(',').count(), CASE_COLUMN_COUNT);
    }

    /// Anyone who knows a case id can file a new-holder claim. If a
    /// refusal closed the door, a stranger filing first and a moderator
    /// refusing it would permanently consume the §5.7 remedy of the
    /// person the device actually belongs to now — the same failure
    /// that moving off the shared `appeal_state` field was meant to
    /// close, arrived at from the other side.
    #[test]
    fn a_refused_claim_does_not_consume_the_next_holders_remedy() {
        let store = Store::in_memory().unwrap();
        let mut case = sample_case("c1");
        case.disposition = Some("ban".into());
        store.put_case(&case).unwrap();

        assert!(store.record_new_holder_claim("c1", "t1", "it is mine now", 3).unwrap());
        assert_eq!(store.case("c1").unwrap().unwrap().new_holder_state, "pending");

        store
            .set_new_holder_state("c1", "refused", Some("pending"), None, "t2",
                                  "new_holder_claim_refused", "hash:a")
            .unwrap();

        // The genuine holder files. The case must go back in the queue.
        assert!(store.record_new_holder_claim("c1", "t3", "here is the receipt", 3).unwrap());
        assert_eq!(
            store.case("c1").unwrap().unwrap().new_holder_state,
            "pending",
            "a refusal of someone else's claim is not an answer to this one"
        );

        // Still bounded: the cap counts filings, not queue entries.
        assert!(store.record_new_holder_claim("c1", "t4", "third", 3).unwrap());
        assert!(!store.record_new_holder_claim("c1", "t5", "fourth", 3).unwrap());
    }

    /// A granted claim has already cleared the marks. There is no
    /// remedy left to ask for, so a later filing is logged without
    /// re-queueing the case.
    #[test]
    fn a_granted_claim_is_not_re_queued() {
        let store = Store::in_memory().unwrap();
        let mut case = sample_case("c1");
        case.new_holder_state = "granted".into();
        store.put_case(&case).unwrap();

        assert!(store.record_new_holder_claim("c1", "t1", "mine too", 3).unwrap());
        assert_eq!(store.case("c1").unwrap().unwrap().new_holder_state, "granted");
    }

    /// Every claim moves the claim revision, including one filed
    /// against an already-queued case and a supplementary appeal
    /// filing. Neither changes a state or the case document, so the
    /// revision is the only thing that can tell a review page it is
    /// looking at a shorter file than the one it is about to decide.
    #[test]
    fn material_a_reviewer_has_not_seen_moves_the_claim_revision() {
        let store = Store::in_memory().unwrap();
        let mut case = sample_case("c1");
        case.appeal_state = "pending".into();
        store.put_case(&case).unwrap();
        let start = store.case("c1").unwrap().unwrap().claim_revision;

        store.append_claim_event_bounded("c1", "t1", "appeal_filed", "and also", 8).unwrap();
        let after_supplement = store.case("c1").unwrap().unwrap().claim_revision;
        assert!(after_supplement > start, "a supplement is material a reviewer has not read");

        store.record_new_holder_claim("c1", "t2", "mine now", 3).unwrap();
        let after_claim = store.case("c1").unwrap().unwrap().claim_revision;
        assert!(after_claim > after_supplement);

        store.record_new_holder_claim("c1", "t3", "still mine", 3).unwrap();
        assert!(
            store.case("c1").unwrap().unwrap().claim_revision > after_claim,
            "a second claim against an already-queued case is new material too"
        );

        // The case document a model would read is untouched by all of
        // it, which is exactly why `revision` cannot stand in.
        assert_eq!(store.case("c1").unwrap().unwrap().revision, case.revision);
    }
}
