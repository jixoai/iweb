//! 用户原始需求（2026-08-27，add-wasm-host-services 任务 4.4/5.3）：iweb:sql@1.0.0
//! 的 minimal-sqlite-v1 执行面——单参数化语句、S1 owner 终裁方言（DML 白名单
//! select/insert/update/delete；owner 未冻结 DDL，CREATE/ALTER/DROP 一律 invalid-sql）、
//! per-call 隐式事务（S2：无跨调用句柄，宿主绝不从分号文本推断批处理）、结果/行/字节/
//! affected/执行时间/锁等待上限、宿主在 SQLite progress checkpoint 上观测 deadline
//! （epoch 上界；长语句可中断，中断回滚当次事务）。规范权威：specs/wasm-host-sql/
//! spec.md 与 packages/contracts/wasm-host-sql.ts（词法/分析/错误映射逐语义对齐）。
//!
//! 后端连接加固：SQLITE_DBCONFIG_DEFENSIVE；rusqlite 特性面刻意不含
//! load_extension/vtab/functions——扩展加载与虚拟表模块注册在 Rust API 层不存在。

use crate::host_services::policy::SqlLimitsV2;
use crate::host_services::quota::{QuotaError, QuotaLedger};
use rusqlite::types::ValueRef;
use rusqlite::{params_from_iter, Connection, OpenFlags, OptionalExtension};
use std::time::{Duration, Instant};

/// SQL 后端稳定错误码前缀（owner 诊断面）。
pub const WASMD_SQL_BACKEND_INVALID: &str = "WASMD_SQL_BACKEND_INVALID";

/// SQL 服务的调用侧错误（WIT variant ↔ host-call code 的映射面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlError {
    InvalidSql,
    InvalidParameter,
    Constraint,
    Busy,
    QuotaExceeded,
    LimitExceeded,
    Timeout,
    Unavailable,
    Internal,
}

impl SqlError {
    /// host-call frame 的 detailCode（bounded opaque；不含 SQL 文本/参数/路径）。
    pub fn detail_code(self) -> &'static str {
        match self {
            SqlError::InvalidSql => "IWEB_SQL_INVALID_SQL",
            SqlError::InvalidParameter => "IWEB_SQL_INVALID_PARAMETER",
            SqlError::Constraint => "IWEB_SQL_CONSTRAINT",
            SqlError::Busy => "IWEB_SQL_BUSY",
            SqlError::QuotaExceeded => "IWEB_SQL_QUOTA_EXCEEDED",
            SqlError::LimitExceeded => "IWEB_SQL_LIMIT_EXCEEDED",
            SqlError::Timeout => "IWEB_SQL_TIMEOUT",
            SqlError::Unavailable => "IWEB_SQL_UNAVAILABLE",
            SqlError::Internal => "IWEB_SQL_INTERNAL",
        }
    }

    /// host-call frame 的 closed code。
    pub fn host_call_code(self) -> &'static str {
        match self {
            SqlError::InvalidSql | SqlError::InvalidParameter => "INVALID_ARGUMENT",
            SqlError::Constraint => "CONFLICT",
            SqlError::Busy => "BUSY",
            SqlError::QuotaExceeded => "QUOTA_EXCEEDED",
            SqlError::LimitExceeded | SqlError::Timeout => "LIMIT_EXCEEDED",
            SqlError::Unavailable => "UNAVAILABLE",
            SqlError::Internal => "INTERNAL",
        }
    }
}

impl From<QuotaError> for SqlError {
    fn from(error: QuotaError) -> Self {
        match error {
            QuotaError::Exceeded => SqlError::QuotaExceeded,
            QuotaError::Busy => SqlError::Busy,
            QuotaError::Unavailable(_) => SqlError::Unavailable,
        }
    }
}

// ---------------------------------------------------------------------------
// WIT value 域（variant null|integer(s64)|real(float64)|text(string)|blob）
// ---------------------------------------------------------------------------

/// SQL 值（WIT variant 的原生形态；blob 为原始字节）。
#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

/// 参数/结果计量：null=0、integer/real=8（s64/f64 定宽）、text=UTF-8 字节、blob=字节数
///（contracts iwebSqlValueWireBytes 同式；列名另计）。
pub fn sql_value_wire_bytes(value: &SqlValue) -> usize {
    match value {
        SqlValue::Null => 0,
        SqlValue::Integer(_) | SqlValue::Real(_) => 8,
        SqlValue::Text(text) => text.len(),
        SqlValue::Blob(bytes) => bytes.len(),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SqlColumn {
    pub name: String,
    pub value: SqlValue,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SqlRow {
    pub columns: Vec<SqlColumn>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SqlExecuteResult {
    pub rows: Vec<SqlRow>,
    pub affected: u64,
    pub last_insert_id: Option<u64>,
}

// ---------------------------------------------------------------------------
// minimal-sqlite-v1 词法层（contracts tokenizeIwebSqlStatement 同式移植）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Token {
    Word(String),
    QuotedIdentifier,
    StringLiteral,
    BlobLiteral,
    Number,
    Placeholder(Option<u32>),
    Punct(char),
    Semicolon,
}

/// 词法错误码（owner 诊断面；不回显 SQL 文本）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlLexicalCode {
    NulByte,
    Unterminated,
    BlobLiteralInvalid,
    PlaceholderIndexInvalid,
    NamedPlaceholderDenied,
    TokenInvalid,
}

const ASCII_WHITESPACE: &[u8] = b" \t\n\r\x0c\x0b";
const PUNCT_CHARS: &[u8] = b"(),.*+-/%=<>!~&|^";

fn is_word_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_word_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// 词法扫描（与 contracts 相同的 fail-closed 选择：NUL 拒绝、命名占位拒绝、
/// 未闭合字面量/标识符拒绝）。
pub(crate) fn tokenize_statement(statement: &str) -> Result<Vec<Token>, SqlLexicalCode> {
    let bytes = statement.as_bytes();
    if bytes.contains(&0) {
        return Err(SqlLexicalCode::NulByte);
    }
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if ASCII_WHITESPACE.contains(&byte) {
            index += 1;
            continue;
        }
        if byte == b'-' && index + 1 < bytes.len() && bytes[index + 1] == b'-' {
            match bytes[index..].iter().position(|&b| b == b'\n') {
                Some(newline) => index += newline + 1,
                None => index = bytes.len(),
            }
            continue;
        }
        if byte == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'*' {
            let mut cursor = index + 2;
            let mut depth = 1;
            while cursor < bytes.len() && depth > 0 {
                if bytes[cursor] == b'/' && cursor + 1 < bytes.len() && bytes[cursor + 1] == b'*' {
                    depth += 1;
                    cursor += 2;
                } else if bytes[cursor] == b'*' && cursor + 1 < bytes.len() && bytes[cursor + 1] == b'/' {
                    depth -= 1;
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
            if depth > 0 {
                return Err(SqlLexicalCode::Unterminated);
            }
            index = cursor;
            continue;
        }
        if byte == b'\'' {
            let mut cursor = index + 1;
            loop {
                match bytes[cursor..].iter().position(|&b| b == b'\'') {
                    None => return Err(SqlLexicalCode::Unterminated),
                    Some(close) => {
                        if close + cursor + 1 < bytes.len() && bytes[cursor + close + 1] == b'\'' {
                            cursor = cursor + close + 2;
                            continue;
                        }
                        tokens.push(Token::StringLiteral);
                        index = cursor + close + 1;
                        break;
                    }
                }
            }
            continue;
        }
        if (byte == b'x' || byte == b'X') && index + 1 < bytes.len() && bytes[index + 1] == b'\'' {
            match bytes[index + 2..].iter().position(|&b| b == b'\'') {
                None => return Err(SqlLexicalCode::Unterminated),
                Some(close) => {
                    let hex = &bytes[index + 2..index + 2 + close];
                    if !hex.len().is_multiple_of(2) || !hex.iter().all(u8::is_ascii_hexdigit) {
                        return Err(SqlLexicalCode::BlobLiteralInvalid);
                    }
                    tokens.push(Token::BlobLiteral);
                    index = index + 2 + close + 1;
                }
            }
            continue;
        }
        if byte == b'"' || byte == b'`' {
            let mut cursor = index + 1;
            loop {
                match bytes[cursor..].iter().position(|&b| b == byte) {
                    None => return Err(SqlLexicalCode::Unterminated),
                    Some(close) => {
                        if cursor + close + 1 < bytes.len() && bytes[cursor + close + 1] == byte {
                            cursor = cursor + close + 2;
                            continue;
                        }
                        tokens.push(Token::QuotedIdentifier);
                        index = cursor + close + 1;
                        break;
                    }
                }
            }
            continue;
        }
        if byte == b'[' {
            match bytes[index + 1..].iter().position(|&b| b == b']') {
                None => return Err(SqlLexicalCode::Unterminated),
                Some(close) => {
                    tokens.push(Token::QuotedIdentifier);
                    index = index + 1 + close + 1;
                }
            }
            continue;
        }
        if byte == b'?' {
            let mut digits = String::new();
            let mut cursor = index + 1;
            while cursor < bytes.len() && bytes[cursor].is_ascii_digit() && digits.len() < 6 {
                digits.push(bytes[cursor] as char);
                cursor += 1;
            }
            if !digits.is_empty() {
                let explicit: u32 = digits.parse().map_err(|_| SqlLexicalCode::PlaceholderIndexInvalid)?;
                if explicit < 1 || (cursor < bytes.len() && is_word_char(bytes[cursor])) {
                    return Err(SqlLexicalCode::PlaceholderIndexInvalid);
                }
                tokens.push(Token::Placeholder(Some(explicit)));
                index = cursor;
                continue;
            }
            tokens.push(Token::Placeholder(None));
            index += 1;
            continue;
        }
        if byte == b':' || byte == b'@' || byte == b'$' {
            return Err(SqlLexicalCode::NamedPlaceholderDenied);
        }
        if byte == b';' {
            tokens.push(Token::Semicolon);
            index += 1;
            continue;
        }
        if byte.is_ascii_digit() || (byte == b'.' && index + 1 < bytes.len() && bytes[index + 1].is_ascii_digit()) {
            let start = index;
            index += 1;
            if byte == b'0' && index < bytes.len() && (bytes[index] == b'x' || bytes[index] == b'X') {
                index += 1;
                while index < bytes.len() && bytes[index].is_ascii_hexdigit() {
                    index += 1;
                }
            } else {
                while index < bytes.len() && bytes[index].is_ascii_digit() {
                    index += 1;
                }
                if index < bytes.len() && bytes[index] == b'.' {
                    index += 1;
                    while index < bytes.len() && bytes[index].is_ascii_digit() {
                        index += 1;
                    }
                }
                if index < bytes.len() && (bytes[index] == b'e' || bytes[index] == b'E') {
                    let mut cursor = index + 1;
                    if cursor < bytes.len() && (bytes[cursor] == b'+' || bytes[cursor] == b'-') {
                        cursor += 1;
                    }
                    if cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
                        index = cursor;
                        while index < bytes.len() && bytes[index].is_ascii_digit() {
                            index += 1;
                        }
                    }
                }
            }
            if index < bytes.len() && is_word_start(bytes[index]) {
                return Err(SqlLexicalCode::TokenInvalid);
            }
            debug_assert!(index > start);
            tokens.push(Token::Number);
            continue;
        }
        if is_word_start(byte) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_word_char(bytes[index]) {
                index += 1;
            }
            tokens.push(Token::Word(statement[start..index].to_string()));
            continue;
        }
        if PUNCT_CHARS.contains(&byte) {
            tokens.push(Token::Punct(byte as char));
            index += 1;
            continue;
        }
        return Err(SqlLexicalCode::TokenInvalid);
    }
    Ok(tokens)
}

/// 语句分析结果（方言门 + 参数计数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatementAnalysis {
    pub kind: SqlStatementKind,
    pub parameter_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlStatementKind {
    Select,
    Insert,
    Update,
    Delete,
}

impl SqlStatementKind {
    pub fn is_mutation(&self) -> bool {
        !matches!(self, SqlStatementKind::Select)
    }
}

const STATEMENT_KEYWORD_DENYLIST: &[&str] = &["attach", "detach", "pragma"];
const EXTENSION_FUNCTION_DENYLIST: &[&str] = &["load_extension", "fts3_tokenizer"];
const FILE_FUNCTION_DENYLIST: &[&str] = &["readfile", "writefile", "edit"];
const DML_KINDS: &[&str] = &["select", "insert", "update", "delete"];

/// 静态方言校验（analyzeIwebSqlTokens 同式）：单语句、DML 白名单、WITH 拒绝、
/// denylist 任意位置（attach/detach/pragma）/调用位置（load_extension 等 +
/// pragma_* 前缀）、参数计数上限。
pub(crate) fn analyze_statement(tokens: Vec<Token>, limits: &SqlLimitsV2) -> Result<StatementAnalysis, SqlError> {
    // 单语句：首个分号必须是最后一个 token。
    let first_semicolon = tokens.iter().position(|token| *token == Token::Semicolon);
    let body: Vec<Token> = match first_semicolon {
        Some(position) => {
            if position != tokens.len() - 1 {
                return Err(SqlError::InvalidSql); // 分号脚本。
            }
            tokens[..tokens.len() - 1].to_vec()
        }
        None => tokens,
    };
    if body.is_empty() {
        return Err(SqlError::InvalidSql);
    }
    let leading = match &body[0] {
        Token::Word(word) => word.to_ascii_lowercase(),
        _ => return Err(SqlError::InvalidSql),
    };
    if leading == "with" {
        return Err(SqlError::InvalidSql); // WITH/CTE 越界。
    }
    let kind = match DML_KINDS.iter().position(|candidate| *candidate == leading) {
        Some(0) => SqlStatementKind::Select,
        Some(1) => SqlStatementKind::Insert,
        Some(2) => SqlStatementKind::Update,
        Some(3) => SqlStatementKind::Delete,
        _ => return Err(SqlError::InvalidSql), // DDL 未冻结：CREATE/ALTER/DROP 拒绝。
    };
    for position in 0..body.len() {
        let word = match &body[position] {
            Token::Word(word) => word.to_ascii_lowercase(),
            _ => continue,
        };
        if STATEMENT_KEYWORD_DENYLIST.contains(&word.as_str()) {
            return Err(SqlError::InvalidSql);
        }
        let in_call_position = matches!(body.get(position + 1), Some(Token::Punct('(')));
        if in_call_position {
            if EXTENSION_FUNCTION_DENYLIST.contains(&word.as_str()) || FILE_FUNCTION_DENYLIST.contains(&word.as_str()) {
                return Err(SqlError::InvalidSql);
            }
            if word.starts_with("pragma_") {
                return Err(SqlError::InvalidSql);
            }
        }
    }
    // 参数计数：裸 ? 取当前最大序号 + 1，?NNN 显式（SQLite 语义）。
    let mut largest = 0usize;
    for token in &body {
        if let Token::Placeholder(explicit) = token {
            largest = match explicit {
                None => largest + 1,
                Some(index) => largest.max(*index as usize),
            };
        }
    }
    if largest > limits.max_parameters as usize {
        return Err(SqlError::LimitExceeded);
    }
    Ok(StatementAnalysis { kind, parameter_count: largest })
}

/// 语句 + 参数的完整 preflight（validateIwebSqlExecuteRequest 同式；一切在执行前）。
pub fn validate_execute_request(
    statement: &str,
    parameters: &[SqlValue],
    limits: &SqlLimitsV2,
) -> Result<StatementAnalysis, SqlError> {
    if statement.is_empty() {
        return Err(SqlError::InvalidSql);
    }
    if statement.len() > limits.statement_max_bytes as usize {
        return Err(SqlError::LimitExceeded);
    }
    let tokens = tokenize_statement(statement).map_err(|_| SqlError::InvalidSql)?;
    let analysis = analyze_statement(tokens, limits)?;
    if parameters.len() > limits.max_parameters as usize {
        return Err(SqlError::LimitExceeded);
    }
    let mut parameter_bytes = 0usize;
    for value in parameters {
        parameter_bytes += sql_value_wire_bytes(value);
        if parameter_bytes > limits.parameter_max_bytes as usize {
            return Err(SqlError::LimitExceeded);
        }
    }
    if parameters.len() != analysis.parameter_count {
        return Err(SqlError::InvalidParameter);
    }
    Ok(analysis)
}

fn value_ref_to_sql_value(value: ValueRef<'_>) -> SqlValue {
    match value {
        ValueRef::Null => SqlValue::Null,
        ValueRef::Integer(int) => SqlValue::Integer(int),
        ValueRef::Real(real) => SqlValue::Real(real),
        ValueRef::Text(text) => SqlValue::Text(String::from_utf8_lossy(text).into_owned()),
        ValueRef::Blob(blob) => SqlValue::Blob(blob.to_vec()),
    }
}

fn sql_value_to_rusqlite(value: &SqlValue) -> rusqlite::types::Value {
    match value {
        SqlValue::Null => rusqlite::types::Value::Null,
        SqlValue::Integer(int) => rusqlite::types::Value::Integer(*int),
        SqlValue::Real(real) => {
            if real.is_finite() {
                rusqlite::types::Value::Real(*real)
            } else {
                rusqlite::types::Value::Null // NaN/Inf 不入 SQLite（fail-closed 投影）。
            }
        }
        SqlValue::Text(text) => rusqlite::types::Value::Text(text.clone()),
        SqlValue::Blob(bytes) => rusqlite::types::Value::Blob(bytes.clone()),
    }
}

// ---------------------------------------------------------------------------
// sql.sqlite3 后端
// ---------------------------------------------------------------------------

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS sql_operations (
  operation_id TEXT PRIMARY KEY,
  reservation_id TEXT NOT NULL,
  proof_digest TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  affected INTEGER NOT NULL DEFAULT 0,
  last_insert_id INTEGER
);
";

/// Durable SQL operation marker used by replay recovery.  It is written in
/// the same transaction as the DML and therefore proves whether the mutation
/// committed even when the host response was lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlOperationMarker {
    pub operation_id: String,
    pub reservation_id: String,
    pub proof_digest: String,
    pub affected: u64,
    pub last_insert_id: Option<u64>,
}

/// sql.sqlite3 后端（每应用一份）。
pub struct SqlBackend {
    conn: Connection,
    pub quarantined: Option<&'static str>,
    lock: std::sync::Mutex<()>,
}

impl SqlBackend {
    pub fn new(conn: Connection) -> Result<Self, SqlError> {
        conn.execute_batch(SCHEMA).map_err(|_| SqlError::Unavailable)?;
        // Upgrade databases created by the first pass without weakening the
        // fail-closed rule: old rows retain NULL result metadata and are
        // rejected by recovery instead of being replayed as a guessed result.
        let _ = conn.execute("ALTER TABLE sql_operations ADD COLUMN affected INTEGER NOT NULL DEFAULT 0", []);
        let _ = conn.execute("ALTER TABLE sql_operations ADD COLUMN last_insert_id INTEGER", []);
        conn.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(|_| SqlError::Unavailable)?;
        Ok(Self { conn, quarantined: None, lock: std::sync::Mutex::new(()) })
    }

    /// 恢复扫描用的宿主侧连接访问（绝不暴露给组件；无 path/handle 泄漏面）。
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// 单语句执行（隐式单调用事务；mutation 与 marker 同事务原子提交）。
    /// deadline 在分配前与 SQLite progress checkpoint 上观测；超时/中断回滚当次
    /// 事务并返回稳定错误（TIMEOUT/limit-exceeded 域）。
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        &mut self,
        statement: &str,
        parameters: &[SqlValue],
        ledger: &mut QuotaLedger,
        envelope_bytes: u64,
        limits: &SqlLimitsV2,
        now_ms: u64,
        deadline: Instant,
    ) -> Result<SqlExecuteResult, SqlError> {
        let operation_id = uuid::Uuid::now_v7().hyphenated().to_string();
        self.execute_with_operation_id(
            statement,
            parameters,
            ledger,
            envelope_bytes,
            limits,
            now_ms,
            deadline,
            &operation_id,
        )
    }

    /// 与 host-call replay claim 共用 operation marker 的执行入口。
    /// 对只读语句 operationId 不会写入后端；对 mutation 它与 reservation/marker
    /// 在同一条恢复链上保持稳定。
    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_operation_id(
        &mut self,
        statement: &str,
        parameters: &[SqlValue],
        ledger: &mut QuotaLedger,
        envelope_bytes: u64,
        limits: &SqlLimitsV2,
        now_ms: u64,
        deadline: Instant,
        operation_id: &str,
    ) -> Result<SqlExecuteResult, SqlError> {
        // 字段分裂借用：锁 guard 与连接的可变借用互不冲突。
        let Self { conn, quarantined, lock } = self;
        if quarantined.is_some() {
            return Err(SqlError::Unavailable);
        }
        // 锁等待上限：并发调用在 lockWaitMaxMs 内拿不到后端锁 → busy（无界等待拒绝）。
        let _guard = lock_with_timeout(lock, Duration::from_millis(limits.lock_wait_max_ms))?;
        // 「observed before allocation」：进入前先看 deadline。
        if Instant::now() >= deadline {
            return Err(SqlError::Timeout);
        }
        let analysis = validate_execute_request(statement, parameters, limits)?;
        // mutation 的保守预留：profile 未冻结独立预留字段——reserve 全部剩余额度
        //（有限、覆盖任意单语句增长；并发 mutation 经 ledger 串行化）。replay TTL
        // 取 wasmd 内部派生常量（契约留白，上报）。
        let reservation = if analysis.kind.is_mutation() {
            let reservation = ledger.reserve_remaining(
                "sql",
                operation_id,
                envelope_bytes,
                now_ms,
                crate::host_services::policy::HOST_CALL_REPLAY_TTL_MS,
            )?;
            Some((operation_id.to_string(), reservation))
        } else {
            None
        };
        // progress checkpoint：deadline 到点即中断 SQLite（回滚当前虚拟机）。
        conn.progress_handler(1_000, Some(move || Instant::now() >= deadline))
            .map_err(|_| SqlError::Internal)?;
        let result = run_statement(conn, statement, parameters, limits, deadline, &reservation, now_ms);
        let _ = conn.progress_handler(1_000, None::<fn() -> bool>);
        match (result, reservation) {
            (Ok(result), Some((_operation_id, reservation))) => {
                // backend commit 与 marker 已在 run_statement 的显式事务内原子完成；
                // 此处在 durable 之后做 ledger finalize（失败 → quarantine，绝不报 quota no-op）。
                let measured = QuotaLedger::measure_sqlite_file_bytes(conn).map_err(SqlError::from)?;
                if let Err(error) = ledger.finalize(&reservation, measured) {
                    *quarantined = Some(WASMD_SQL_BACKEND_INVALID);
                    return Err(error.into());
                }
                Ok(result)
            }
            (Ok(result), None) => Ok(result),
            (Err(error), Some((_operation_id, reservation))) => {
                let _ = ledger.release(&reservation.reservation_id);
                Err(error)
            }
            (Err(error), None) => Err(error),
        }
    }

    pub fn has_operation_marker(&self, operation_id: &str) -> Result<bool, SqlError> {
        let found: Option<i64> = self
            .conn
            .query_row("SELECT 1 FROM sql_operations WHERE operation_id = ?1", rusqlite::params![operation_id], |row| row.get(0))
            .optional()
            .map_err(|_| SqlError::Internal)?;
        Ok(found.is_some())
    }

    /// Return the complete durable marker for one operation.
    pub fn operation_marker(&self, operation_id: &str) -> Result<Option<SqlOperationMarker>, SqlError> {
        self.conn
            .query_row(
                "SELECT operation_id, reservation_id, proof_digest, affected, last_insert_id
                 FROM sql_operations WHERE operation_id = ?1",
                rusqlite::params![operation_id],
                |row| {
                    let affected = row.get::<_, i64>(3)?.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?;
                    let last_insert_id = row
                        .get::<_, Option<i64>>(4)?
                        .map(|value| value.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
                        .transpose()?;
                    Ok(SqlOperationMarker {
                        operation_id: row.get(0)?,
                        reservation_id: row.get(1)?,
                        proof_digest: row.get(2)?,
                        affected,
                        last_insert_id,
                    })
                },
            )
            .optional()
            .map_err(|_| SqlError::Internal)
    }

    pub fn list_operation_ids(&self) -> Result<Vec<String>, SqlError> {
        let mut statement = self.conn.prepare("SELECT operation_id FROM sql_operations").map_err(|_| SqlError::Internal)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| SqlError::Internal)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SqlError::Internal)?;
        Ok(rows)
    }

    pub fn quarantine_on_orphan_marker(&mut self, ledger_operation_ids: &[String]) {
        let known = self.list_operation_ids().unwrap_or_default();
        if known.iter().any(|id| !ledger_operation_ids.contains(id)) {
            self.quarantined = Some(WASMD_SQL_BACKEND_INVALID);
        }
    }
}

/// SQLite prepare/step 错误 → SqlError（无 SQL 文本/路径外泄）。
fn map_prepare_error(error: rusqlite::Error) -> SqlError {
    if let rusqlite::Error::SqliteFailure(code, _) = &error {
        if code.code == rusqlite::ErrorCode::OperationInterrupted {
            // 中断源只有 progress handler 的 deadline 观测。
            return SqlError::Timeout;
        }
        if code.code == rusqlite::ErrorCode::DatabaseBusy || code.code == rusqlite::ErrorCode::DatabaseLocked {
            return SqlError::Busy;
        }
        if code.code == rusqlite::ErrorCode::ConstraintViolation {
            return SqlError::Constraint;
        }
    }
    // 语法/语义错误（含 no such table）落在 invalid-sql 域；参数绑定类型错误单列。
    if matches!(error, rusqlite::Error::InvalidParameterName(_) | rusqlite::Error::ToSqlConversionFailure(_)) {
        return SqlError::InvalidParameter;
    }
    SqlError::InvalidSql
}

fn map_sqlite_error(error: rusqlite::Error, _deadline: Instant) -> SqlError {
    map_prepare_error(error)
}

/// 真实执行：SELECT 流式读行并在迭代中强制 maxRows/resultMaxBytes（拒绝截断
/// 成功）；mutation 在显式单事务内与 marker 一起原子提交（不先行执行）。
#[allow(clippy::too_many_arguments)]
fn run_statement(
    conn: &mut Connection,
    statement: &str,
    parameters: &[SqlValue],
    limits: &SqlLimitsV2,
    deadline: Instant,
    reservation: &Option<(String, crate::host_services::quota::ReservationRecordV2)>,
    now_ms: u64,
) -> Result<SqlExecuteResult, SqlError> {
    let values: Vec<rusqlite::types::Value> = parameters.iter().map(sql_value_to_rusqlite).collect();
    match reservation {
        None => {
            // 只读路径：语句即隐式单调用事务（SQLite autocommit 下的单 SELECT）。
            let mut prepared = conn.prepare(statement).map_err(map_prepare_error)?;
            let column_count = prepared.column_count();
            let column_names: Vec<String> = (0..column_count)
                .map(|index| prepared.column_name(index).unwrap_or_default().to_string())
                .collect();
            let mut rows_out: Vec<SqlRow> = Vec::new();
            let mut result_bytes: usize = 0usize;
            let mut raw_rows = prepared.query(params_from_iter(values.iter())).map_err(map_prepare_error)?;
            loop {
                if Instant::now() >= deadline {
                    return Err(SqlError::Timeout);
                }
                let row = match raw_rows.next().map_err(|error| map_sqlite_error(error, deadline))? {
                    Some(row) => row,
                    None => break,
                };
                if rows_out.len() as u64 >= limits.max_rows {
                    return Err(SqlError::LimitExceeded); // 截断结果绝不冒充完整成功。
                }
                let mut columns = Vec::with_capacity(column_count);
                for (index, name) in column_names.iter().enumerate() {
                    let value = value_ref_to_sql_value(row.get_ref(index).map_err(|_| SqlError::Internal)?);
                    result_bytes += name.len() + sql_value_wire_bytes(&value);
                    if result_bytes > limits.result_max_bytes as usize {
                        return Err(SqlError::LimitExceeded);
                    }
                    columns.push(SqlColumn { name: name.clone(), value });
                }
                rows_out.push(SqlRow { columns });
            }
            Ok(SqlExecuteResult { rows: rows_out, affected: 0, last_insert_id: None })
        }
        Some((operation_id, reservation_record)) => {
            // mutation 路径：显式单事务 = DML + marker，原子提交或整体无效。
            let tx = conn.transaction().map_err(|_| SqlError::Internal)?;
            let changed = {
                let mut statement_handle = tx.prepare(statement).map_err(map_prepare_error)?;
                statement_handle
                    .execute(params_from_iter(values.iter()))
                    .map_err(|error| map_sqlite_error(error, deadline))?
            };
            // Capture the application DML row id before inserting the marker;
            // querying it after the marker insert would return the marker's
            // rowid and make replay non-deterministic.
            let last_insert_id = tx.last_insert_rowid();
            if changed as u64 > limits.max_affected_rows {
                // 上限后置检查：诚实报错（事务回滚，绝不返回截断成功）。
                let _ = tx.rollback();
                return Err(SqlError::LimitExceeded);
            }
            tx.execute(
                "INSERT INTO sql_operations (operation_id, reservation_id, proof_digest, created_at_ms, affected, last_insert_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    operation_id,
                    reservation_record.reservation_id,
                    reservation_record.reservation_proof_digest,
                    now_ms as i64,
                    changed as i64,
                    if last_insert_id > 0 { Some(last_insert_id) } else { None }
                ],
            )
            .map_err(|_| SqlError::Internal)?;
            tx.commit().map_err(|_| SqlError::Internal)?;
            Ok(SqlExecuteResult {
                rows: Vec::new(),
                affected: changed as u64,
                last_insert_id: if last_insert_id > 0 { Some(last_insert_id as u64) } else { None },
            })
        }
    }
}

/// 带期限的互斥进入（lockWaitMaxMs 上界；超时 → busy，无第三方依赖）。
fn lock_with_timeout(lock: &std::sync::Mutex<()>, timeout: Duration) -> Result<std::sync::MutexGuard<'_, ()>, SqlError> {
    let deadline = Instant::now() + timeout;
    loop {
        match lock.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(SqlError::Internal),
            Err(std::sync::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(SqlError::Busy);
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
}

/// 打开（或初始化）后端连接（调用方负责目录/权限加固）。
pub fn open_sql_connection(path: &std::path::Path) -> Result<Connection, SqlError> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE).map_err(|_| SqlError::Unavailable)
}

/// 宿主侧通道（测试预置 schema 与恢复流程用）：不经方言门，绝不暴露给组件。
#[cfg(test)]
pub(crate) fn host_side_exec(conn: &Connection, sql: &str) -> Result<(), SqlError> {
    conn.execute_batch(sql).map_err(|_| SqlError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        backend: SqlBackend,
        ledger: QuotaLedger,
    }

    fn fixture() -> (Fixture, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let conn = open_sql_connection(&dir.path().join("sql.sqlite3")).expect("sql db");
        // 宿主侧预置 schema（DDL 未冻结：应用不能 CREATE；表由宿主/恢复流程预置）。
        host_side_exec(&conn, "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL);").expect("seed schema");
        let backend = SqlBackend::new(conn).expect("backend");
        let ledger = QuotaLedger::new(
            Connection::open(dir.path().join("quota.sqlite3")).expect("quota db"),
            "alpha",
        )
        .expect("ledger");
        ((Fixture { backend, ledger }), dir)
    }

    fn limits() -> SqlLimitsV2 {
        SqlLimitsV2 {
            statement_max_bytes: 8_192,
            max_parameters: 128,
            parameter_max_bytes: 65_536,
            max_rows: 1_000,
            result_max_bytes: 262_144,
            max_affected_rows: 4_096,
            execution_max_ms: 5_000,
            lock_wait_max_ms: 2_000,
            max_concurrent_calls: 2,
        }
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[test]
    fn parameterized_mutation_commits_atomically_with_marker() {
        let (mut fixture, _dir) = fixture();
        let result = fixture
            .backend
            .execute(
                "INSERT INTO notes (body) VALUES (?1)",
                &[SqlValue::Text("hello".into())],
                &mut fixture.ledger,
                1_048_576,
                &limits(),
                0,
                deadline(),
            )
            .expect("insert");
        assert_eq!(result.affected, 1);
        assert!(result.last_insert_id.is_some());
        let markers = fixture.backend.list_operation_ids().expect("markers");
        assert_eq!(markers.len(), 1, "marker committed with the mutation");
        // 读回：同连接可见（隐式单调用事务提交）。
        let read = fixture
            .backend
            .execute("SELECT id, body FROM notes WHERE body = ?", &[SqlValue::Text("hello".into())], &mut fixture.ledger, 1_048_576, &limits(), 0, deadline())
            .expect("select");
        assert_eq!(read.rows.len(), 1);
        assert_eq!(read.rows[0].columns.len(), 2);
        assert_eq!(read.rows[0].columns[1].value, SqlValue::Text("hello".into()));
    }

    #[test]
    fn dialect_denylist_rejects_scripts_attach_pragma_and_functions() {
        let (mut fixture, _dir) = fixture();
        let cases: &[&str] = &[
            "INSERT INTO notes (body) VALUES ('a'); INSERT INTO notes (body) VALUES ('b')",
            "ATTACH DATABASE '/etc/passwd' AS x",
            "DETACH DATABASE x",
            "PRAGMA journal_mode = WAL",
            "SELECT load_extension('/tmp/evil.so')",
            "SELECT fts3_tokenizer('simple')",
            "SELECT readfile('/etc/passwd')",
            "SELECT writefile('/tmp/x', 'y')",
            "SELECT edit('vi', 'x')",
            "SELECT * FROM pragma_table_info('notes')",
            "CREATE TABLE evil (id INTEGER)",
            "ALTER TABLE notes ADD COLUMN x INTEGER",
            "DROP TABLE notes",
            "WITH c(x) AS (SELECT 1) SELECT x FROM c",
            "SELECT :named FROM notes",
            "SELECT @named FROM notes",
            "SELECT $named FROM notes",
            "SELECT 'unterminated FROM notes",
            "",
        ];
        for statement in cases {
            let error = fixture
                .backend
                .execute(statement, &[], &mut fixture.ledger, 1_048_576, &limits(), 0, deadline())
                .unwrap_err();
            assert_eq!(error, SqlError::InvalidSql, "must reject {statement:?} with invalid-sql");
        }
        // 数据库保持未变：notes 表没有任何插入。
        let read = fixture
            .backend
            .execute("SELECT id FROM notes", &[], &mut fixture.ledger, 1_048_576, &limits(), 0, deadline())
            .expect("select");
        assert_eq!(read.rows.len(), 0, "denied statements leave the database unchanged");
        assert!(fixture.backend.list_operation_ids().expect("markers").is_empty());
    }

    #[test]
    fn parameter_count_and_bounds_are_enforced() {
        let (mut fixture, _dir) = fixture();
        // 占位计数 ≠ 参数数 → invalid-parameter。
        let error = fixture
            .backend
            .execute("SELECT id FROM notes WHERE id = ? AND body = ?", &[SqlValue::Integer(1)], &mut fixture.ledger, 1_048_576, &limits(), 0, deadline())
            .unwrap_err();
        assert_eq!(error, SqlError::InvalidParameter);
        // ?NNN 显式序号（SQLite 语义：最大序号即计数）。
        fixture
            .backend
            .execute("SELECT id FROM notes WHERE id = ?2 AND body = ?1", &[SqlValue::Text("x".into()), SqlValue::Integer(1)], &mut fixture.ledger, 1_048_576, &limits(), 0, deadline())
            .expect("explicit indices");
        // 语句字节上限。
        let long = format!("SELECT id FROM notes WHERE body = '{}'", "x".repeat(9_000));
        let error = fixture
            .backend
            .execute(&long, &[], &mut fixture.ledger, 1_048_576, &limits(), 0, deadline())
            .unwrap_err();
        assert_eq!(error, SqlError::LimitExceeded);
    }

    #[test]
    fn result_row_and_byte_limits_reject_truncated_success() {
        let (mut fixture, _dir) = fixture();
        host_side_exec(&fixture.backend.conn, "INSERT INTO notes (body) VALUES ('a'),('b'),('c'),('d');").expect("seed");
        // maxRows = 3：第四行触发 limit-exceeded（无部分成功）。
        let mut tight = limits();
        tight.max_rows = 3;
        let error = fixture
            .backend
            .execute("SELECT id, body FROM notes", &[], &mut fixture.ledger, 1_048_576, &tight, 0, deadline())
            .unwrap_err();
        assert_eq!(error, SqlError::LimitExceeded);
        // resultMaxBytes：行字节超界。
        let mut tight = limits();
        tight.result_max_bytes = 4;
        let error = fixture
            .backend
            .execute("SELECT id, body FROM notes", &[], &mut fixture.ledger, 1_048_576, &tight, 0, deadline())
            .unwrap_err();
        assert_eq!(error, SqlError::LimitExceeded);
    }

    #[test]
    fn constraint_violation_maps_and_rolls_back() {
        let (mut fixture, _dir) = fixture();
        fixture
            .backend
            .execute("INSERT INTO notes (body) VALUES ('one')", &[], &mut fixture.ledger, 1_048_576, &limits(), 0, deadline())
            .expect("first insert");
        let error = fixture
            .backend
            .execute("INSERT INTO notes (id, body) VALUES (1, 'dup')", &[], &mut fixture.ledger, 1_048_576, &limits(), 0, deadline())
            .unwrap_err();
        assert_eq!(error, SqlError::Constraint);
        let read = fixture
            .backend
            .execute("SELECT COUNT(id) FROM notes", &[], &mut fixture.ledger, 1_048_576, &limits(), 0, deadline())
            .expect("count");
        let count = match &read.rows[0].columns[0].value {
            SqlValue::Integer(value) => *value,
            other => panic!("expected integer, got {other:?}"),
        };
        assert_eq!(count, 1, "constraint failure rolls back the implicit transaction");
    }

    #[test]
    fn quota_exceeded_rejects_mutation_before_execution() {
        let (mut fixture, _dir) = fixture();
        // envelope 恰为当前实测用量（page 粒度）：剩余额度为 0，第一条 mutation 即
        // 在写前被拒（语句不执行、无 marker）。
        // envelope 恰等于当前实测用量：首次 committed=0 → reserve_remaining 预留全部
        // envelope（合法）；提交后 committed=measured ≥ envelope → 剩余 0 → 第二条拒绝。
        let envelope = QuotaLedger::measure_sqlite_file_bytes(fixture.backend.connection()).expect("measured");
        fixture
            .backend
            .execute("INSERT INTO notes (body) VALUES ('first')", &[], &mut fixture.ledger, envelope, &limits(), 0, deadline())
            .expect("first reserves the full remaining envelope");
        let error = fixture
            .backend
            .execute("INSERT INTO notes (body) VALUES ('second')", &[], &mut fixture.ledger, envelope, &limits(), 0, deadline())
            .unwrap_err();
        assert_eq!(error, SqlError::QuotaExceeded, "second mutation has no remaining envelope");
        let read = fixture
            .backend
            .execute("SELECT COUNT(id) FROM notes", &[], &mut fixture.ledger, 1_048_576, &limits(), 0, deadline())
            .expect("count");
        match &read.rows[0].columns[0].value {
            SqlValue::Integer(value) => assert_eq!(*value, 1, "rejected mutation performed no write"),
            other => panic!("expected integer, got {other:?}"),
        }
    }

    #[test]
    fn long_statement_is_interrupted_at_deadline() {
        let (mut fixture, _dir) = fixture();
        // 宿主侧预置 64 行非索引 pad 列：6 表自连接 ≈ 6.9e10 组合，远超 50ms 预算。
        host_side_exec(&fixture.backend.conn, "CREATE TABLE big (id INTEGER PRIMARY KEY, pad TEXT);").expect("big");
        host_side_exec(
            &fixture.backend.conn,
            "INSERT INTO big (pad) WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 64) SELECT 'x' FROM c;",
        )
        .expect("seed");
        let interrupt_at = Instant::now() + Duration::from_millis(50);
        let started = Instant::now();
        let error = fixture
            .backend
            .execute(
                "SELECT COUNT(b1.id) FROM big b1, big b2, big b3, big b4, big b5, big b6 WHERE b1.pad = b2.pad AND b2.pad = b3.pad AND b3.pad = b4.pad AND b4.pad = b5.pad AND b5.pad = b6.pad",
                &[],
                &mut fixture.ledger,
                1_048_576,
                &limits(),
                0,
                interrupt_at,
            )
            .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(3), "cross product must be interrupted at the deadline");
        assert_eq!(error, SqlError::Timeout, "progress-checkpoint interruption maps to timeout");
        // 中断后连接可复用（当前事务已回滚）：普通查询立即成功。
        let read = fixture
            .backend
            .execute("SELECT COUNT(id) FROM big", &[], &mut fixture.ledger, 1_048_576, &limits(), 0, deadline())
            .expect("connection reusable after interrupt");
        match &read.rows[0].columns[0].value {
            SqlValue::Integer(value) => assert_eq!(*value, 64),
            other => panic!("expected integer, got {other:?}"),
        }
    }

    #[test]
    fn quarantined_backend_refuses_service() {
        let (mut fixture, _dir) = fixture();
        fixture.backend.quarantined = Some(WASMD_SQL_BACKEND_INVALID);
        assert_eq!(
            fixture.backend.execute("SELECT id FROM notes", &[], &mut fixture.ledger, 1_048_576, &limits(), 0, deadline()).unwrap_err(),
            SqlError::Unavailable
        );
    }

    #[test]
    fn blob_text_and_real_values_round_trip() {
        let (mut fixture, _dir) = fixture();
        host_side_exec(&fixture.backend.conn, "CREATE TABLE mixed (id INTEGER PRIMARY KEY, payload BLOB, score REAL, label TEXT);").expect("schema");
        fixture
            .backend
            .execute(
                "INSERT INTO mixed (payload, score, label) VALUES (?1, ?2, ?3)",
                &[SqlValue::Blob(b"\x00\x01\xff".to_vec()), SqlValue::Real(1.5), SqlValue::Text("héllo".into())],
                &mut fixture.ledger,
                1_048_576,
                &limits(),
                0,
                deadline(),
            )
            .expect("insert mixed");
        let read = fixture
            .backend
            .execute("SELECT payload, score, label FROM mixed", &[], &mut fixture.ledger, 1_048_576, &limits(), 0, deadline())
            .expect("select mixed");
        let row = &read.rows[0];
        assert_eq!(row.columns[0].value, SqlValue::Blob(b"\x00\x01\xff".to_vec()));
        assert_eq!(row.columns[1].value, SqlValue::Real(1.5));
        assert_eq!(row.columns[2].value, SqlValue::Text("héllo".into()));
    }
}
