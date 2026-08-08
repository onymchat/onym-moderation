//! Durable state: registered mandates, reporter track records, reports,
//! cases, and issued verdicts.

use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::Error;

pub struct Store {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct MandateRecord {
    pub mandate_ref: String,
    pub user_key: String,
    pub device_binding: String,
    pub classes: Vec<String>,
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
            CREATE TABLE IF NOT EXISTS mandates (
                mandate_ref    TEXT PRIMARY KEY,
                user_key       TEXT NOT NULL,
                device_binding TEXT NOT NULL,
                classes        TEXT NOT NULL,
                raw            BLOB NOT NULL,
                accepted_at    TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS mandates_by_user ON mandates (user_key);

            CREATE TABLE IF NOT EXISTS reporters (
                user_key  TEXT PRIMARY KEY,
                upheld    INTEGER NOT NULL DEFAULT 0,
                dismissed INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS reports (
                report_id  TEXT PRIMARY KEY,
                reporter   TEXT NOT NULL,
                accused    TEXT NOT NULL,
                class_id   TEXT NOT NULL,
                case_id    TEXT,
                weight     REAL NOT NULL,
                raw        BLOB NOT NULL,
                filed_at   TEXT NOT NULL
            );

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
                delivered   INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS verdicts_undelivered ON verdicts (delivered);
            "#,
        )
        .map_err(|e| Error::Internal(format!("migrate: {e}")))?;
        Ok(())
    }

    // ─── Mandates ────────────────────────────────────────────────────

    pub fn put_mandate(
        &self,
        record: &MandateRecord,
        raw: &[u8],
        accepted_at: &str,
    ) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO mandates
             (mandate_ref, user_key, device_binding, classes, raw, accepted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                record.mandate_ref,
                record.user_key,
                record.device_binding,
                record.classes.join(","),
                raw,
                accepted_at
            ],
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
        })
    }

    /// The mandate a user signed naming this authority. Its absence is
    /// what `no_jurisdiction` and `reporter_unconsented` mean.
    pub fn mandate_for_user(&self, user_key: &str) -> Result<Option<MandateRecord>, Error> {
        let conn = self.conn.lock().unwrap();
        let record = conn
            .query_row(
                "SELECT mandate_ref, user_key, device_binding, classes
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
    pub fn record_report_outcome(&self, user_key: &str, upheld: bool) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
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
        conn.execute(
            "INSERT OR REPLACE INTO reports
             (report_id, reporter, accused, class_id, case_id, weight, raw, filed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![report_id, reporter, accused, class_id, case_id, weight, raw, filed_at],
        )?;
        Ok(())
    }

    // ─── Cases ───────────────────────────────────────────────────────

    pub fn put_case(&self, case: &CaseRecord) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
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

    pub fn put_verdict(
        &self,
        verdict_ref: &str,
        case_id: &str,
        disposition: &str,
        raw: &[u8],
        issued_at: &str,
    ) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO verdicts (verdict_ref, case_id, disposition, raw, issued_at, delivered)
             VALUES (?1, ?2, ?3, ?4, ?5, COALESCE((SELECT delivered FROM verdicts WHERE verdict_ref = ?1), 0))",
            params![verdict_ref, case_id, disposition, raw, issued_at],
        )?;
        Ok(())
    }

    pub fn mark_delivered(&self, verdict_ref: &str) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE verdicts SET delivered = 1 WHERE verdict_ref = ?1",
            params![verdict_ref],
        )?;
        Ok(())
    }

    /// Verdicts the interface has not acknowledged yet. Delivery is
    /// retried: a verdict is issued whether or not the interface is
    /// reachable, and an undelivered one is not an undecided case.
    pub fn undelivered_verdicts(&self) -> Result<Vec<(String, Vec<u8>)>, Error> {
        let conn = self.conn.lock().unwrap();
        let mut statement =
            conn.prepare("SELECT verdict_ref, raw FROM verdicts WHERE delivered = 0 ORDER BY issued_at")?;
        let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
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

    #[test]
    fn track_record_accumulates_per_reporter() {
        let store = Store::in_memory().unwrap();
        store.record_report_outcome("onym:key:aa", true).unwrap();
        store.record_report_outcome("onym:key:aa", true).unwrap();
        store.record_report_outcome("onym:key:aa", false).unwrap();
        store.record_report_outcome("onym:key:bb", false).unwrap();

        let a = store.reporter("onym:key:aa").unwrap();
        assert_eq!((a.upheld, a.dismissed), (2, 1));
        let b = store.reporter("onym:key:bb").unwrap();
        assert_eq!((b.upheld, b.dismissed), (0, 1));
        // An unknown reporter is not an error; they simply have no
        // record yet.
        assert_eq!(store.reporter("onym:key:cc").unwrap().upheld, 0);
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
}
