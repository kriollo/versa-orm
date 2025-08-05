// Permitir estos warnings de Clippy temporalmente mientras refactorizamos
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::unnecessary_to_owned)]
#![allow(clippy::unnecessary_get_then_check)]

use chrono::{Duration, Local, TimeZone, Utc};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref LOG_FILE: Mutex<Option<File>> = Mutex::new(None);
}

fn setup_logging(debug: bool) {
    if !debug {
        return;
    }

    // Intentar obtener el directorio padre del binario (donde debería estar el proyecto PHP)
    let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    let project_dir = current_exe
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or_else(|| Path::new("."));
    let log_dir = project_dir.join("logs");

    // Imprimir a stderr para debugging antes de configurar el archivo de log
    eprintln!("[DEBUG] Setting up logging in directory: {:?}", log_dir);

    if !log_dir.exists() {
        if let Err(e) = fs::create_dir_all(&log_dir) {
            eprintln!("Failed to create logs directory {:?}: {}", log_dir, e);
            return;
        }
    }

    let today = Local::now().format("%Y-%m-%d").to_string();
    let log_path = log_dir.join(format!("rust-{}.log", today));

    eprintln!("[DEBUG] Log file path: {:?}", log_path);

    if let Ok(file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        *LOG_FILE.lock().unwrap() = Some(file);
        // Ahora que el archivo está configurado, escribir los mensajes de log
        log_info_msg(&format!(
            "=== VersaORM Rust CLI Session Started at {} ===",
            Local::now().format("%Y-%m-%d %H:%M:%S")
        ));
        log_debug_msg(&format!("Logging configured in directory: {:?}", log_dir));
        log_debug_msg(&format!("Log file path: {:?}", log_path));
    } else {
        eprintln!("Failed to open log file: {:?}", log_path);
    }

    cleanup_old_logs(&log_dir);
}

fn cleanup_old_logs(log_dir: &PathBuf) {
    let seven_days_ago = Utc::now() - Duration::days(7);

    if let Ok(entries) = fs::read_dir(log_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().is_some_and(|ext| ext == "log") {
                if let Some(stem) = path.file_stem() {
                    if let Some(stem_str) = stem.to_str() {
                        if let Ok(date) = chrono::NaiveDate::parse_from_str(stem_str, "%Y-%m-%d") {
                            let datetime = date.and_hms_opt(0, 0, 0).unwrap();
                            if Utc.from_utc_datetime(&datetime) < seven_days_ago {
                                let _ = fs::remove_file(path);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[allow(unused_macros)]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        if let Some(ref mut file) = *LOG_FILE.lock().unwrap() {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
            writeln!(file, "[{}][DEBUG] {}", timestamp, format!($($arg)*)).unwrap();
        }
    };
}

// Public function for other modules to use
pub fn log_debug_msg(msg: &str) {
    if let Ok(mut lock) = LOG_FILE.lock() {
        if let Some(ref mut file) = *lock {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
            if writeln!(file, "[{}][RUST][DEBUG] {}", timestamp, msg).is_ok() {
                let _ = file.flush(); // Asegurar que se escriba inmediatamente
            }
        }
    }
}

// Función adicional para logs de información
pub fn log_info_msg(msg: &str) {
    if let Ok(mut lock) = LOG_FILE.lock() {
        if let Some(ref mut file) = *lock {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
            if writeln!(file, "[{}][RUST][INFO] {}", timestamp, msg).is_ok() {
                let _ = file.flush();
            }
        }
    }
}

// Función adicional para logs de error
pub fn log_error_msg(msg: &str) {
    if let Ok(mut lock) = LOG_FILE.lock() {
        if let Some(ref mut file) = *lock {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
            if writeln!(file, "[{}][RUST][ERROR] {}", timestamp, msg).is_ok() {
                let _ = file.flush();
            }
        }
    }
}

// Módulos del ORM
mod cache;
mod connection;
mod model;
mod query;
mod schema;
mod tests;
mod utils;

use connection::{ConnectionManager, DatabaseConfig};
use query::QueryBuilder;
use schema::SchemaInspector;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RelationMetadata {
    pub name: String,
    #[serde(rename = "type")]
    pub relation_type: String,
    pub related_table: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub foreign_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pivot_table: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub foreign_pivot_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_pivot_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_key: Option<String>,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(value_name = "JSON_INPUT")]
    json_input: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct InputPayload {
    config: DatabaseConfig,
    action: String,
    params: serde_json::Value,
    #[serde(default)]
    freeze_state: FreezeState,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct FreezeState {
    global_frozen: bool,
    #[serde(default)]
    frozen_models: std::collections::HashMap<String, bool>,
}

#[derive(Serialize, Debug)]
struct SuccessResponse<T> {
    status: String,
    data: T,
    metadata: ResponseMetadata,
}

#[derive(Serialize, Debug)]
struct ResponseMetadata {
    execution_time_ms: f64,
    item_count: usize,
}

#[derive(Serialize, Debug)]
struct ErrorResponse {
    status: String,
    error: ErrorDetails,
}

#[derive(Serialize, Debug)]
struct ErrorDetails {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bindings: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<std::collections::HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sql_state: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct QueryParameters {
    table: String,
    method: String,
    #[serde(default)]
    select: Vec<String>,
    #[serde(default)]
    joins: Vec<JoinClause>,
    #[serde(default, rename = "where")]
    wheres: Vec<WhereClause>,
    #[serde(default, rename = "orderBy")]
    order_by: Vec<OrderByClause>,
    #[serde(default, rename = "groupBy")]
    group_by: Vec<String>,
    #[serde(default)]
    having: Vec<HavingClause>,
    limit: Option<i64>,
    offset: Option<i64>,
    #[serde(default)]
    with: Vec<RelationMetadata>,
    data: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct JoinClause {
    #[serde(rename = "type")]
    join_type: String,
    table: String,
    first_col: String,
    operator: String,
    second_col: String,
    // Optional fields for subquery joins
    #[serde(skip_serializing_if = "Option::is_none")]
    subquery: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subquery_bindings: Option<Vec<serde_json::Value>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct WhereClause {
    column: String,
    operator: String,
    value: serde_json::Value,
    #[serde(rename = "type")]
    conjunction: String,
    #[serde(default)]
    bindings: Vec<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
struct OrderByClause {
    column: String,
    direction: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct HavingClause {
    column: String,
    operator: String,
    value: serde_json::Value,
}

#[tokio::main]
async fn main() {
    std::panic::set_hook(Box::new(|panic_info| {
        let error_msg = if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else {
            "Unknown panic occurred".to_string()
        };

        let location = if let Some(location) = panic_info.location() {
            format!(
                " at {}:{}:{}",
                location.file(),
                location.line(),
                location.column()
            )
        } else {
            String::new()
        };

        let response = ErrorResponse {
            status: "error".to_string(),
            error: ErrorDetails {
                code: "PANIC_ERROR".to_string(),
                message: format!("Internal error: {}{}", error_msg, location),
                query: None,
                bindings: None,
                details: None,
                sql_state: None,
            },
        };

        eprintln!("{}", serde_json::to_string(&response).unwrap_or_else(|_|
            r#"{"status":"error","error":{"code":"PANIC_ERROR","message":"Failed to serialize error response"}}"#.to_string()));
    }));

    run_main().await;
}

async fn run_main() {
    let cli = Cli::parse();
    let start_time = Instant::now();

    let json_input = if cli.json_input.starts_with('@') {
        let file_path = &cli.json_input[1..];
        match std::fs::read_to_string(file_path) {
            Ok(content) => content,
            Err(e) => {
                let response = ErrorResponse {
                    status: "error".to_string(),
                    error: ErrorDetails {
                        code: "FILE_READ_ERROR".to_string(),
                        message: format!("Failed to read temporary file '{}': {}", file_path, e),
                        query: None,
                        bindings: None,
                        details: None,
                        sql_state: None,
                    },
                };
                eprintln!("{}", serde_json::to_string(&response).unwrap());
                return;
            }
        }
    } else {
        cli.json_input
    };

    let input_payload: Result<InputPayload, _> = serde_json::from_str(&json_input);

    match input_payload {
        Ok(payload) => {
            setup_logging(payload.config.debug);

            let mut connection_manager = ConnectionManager::new(payload.config);

            if let Err(e) = connection_manager.connect().await {
                let is_debug = connection_manager.is_debug_mode();
                let message = if is_debug {
                    format!("Database connection failed: {}", e)
                } else {
                    "Database connection failed".to_string()
                };

                let mut details = None;
                if is_debug {
                    let mut debug_info = HashMap::new();
                    debug_info.insert(
                        "full_error".to_string(),
                        serde_json::Value::String(e.to_string()),
                    );
                    debug_info.insert(
                        "config".to_string(),
                        serde_json::to_value(connection_manager.get_config())
                            .unwrap_or(serde_json::Value::Null),
                    );
                    details = Some(debug_info);
                }

                let response = ErrorResponse {
                    status: "error".to_string(),
                    error: ErrorDetails {
                        code: "DB_CONN_FAILED".to_string(),
                        message,
                        query: None,
                        bindings: None,
                        details,
                        sql_state: None,
                    },
                };
                eprintln!("{}", serde_json::to_string(&response).unwrap());
                return;
            }

            let result = match payload.action.as_str() {
                "query" | "insert" | "insertGetId" | "update" | "delete" => {
                    handle_query_action(&connection_manager, &payload.params, &payload.freeze_state)
                        .await
                }
                "schema" => handle_schema_action(
                    &connection_manager,
                    &payload.params,
                    &payload.freeze_state,
                )
                .await
                .map_err(|e| (e, None, None)),
                "raw" => {
                    handle_raw_action(&connection_manager, &payload.params, &payload.freeze_state)
                        .await
                }
                "cache" => handle_cache_action(&payload.params).map_err(|e| (e, None, None)),
                _ => Err((format!("Unknown action: {}", payload.action), None, None)),
            };

            let execution_time = start_time.elapsed().as_millis() as f64;

            match result {
                Ok(data) => {
                    let item_count = match &data {
                        serde_json::Value::Array(arr) => arr.len(),
                        serde_json::Value::Null => 0,
                        _ => 1,
                    };

                    let response = SuccessResponse {
                        status: "success".to_string(),
                        data,
                        metadata: ResponseMetadata {
                            execution_time_ms: execution_time,
                            item_count,
                        },
                    };
                    println!("{}", serde_json::to_string(&response).unwrap());
                }
                Err((error_msg, query, bindings)) => {
                    let is_debug = connection_manager.is_debug_mode();
                    let message = if is_debug {
                        error_msg.clone()
                    } else {
                        "Database operation failed".to_string()
                    };

                    let mut details = None;
                    if is_debug {
                        let mut debug_info = HashMap::new();
                        debug_info.insert(
                            "full_error".to_string(),
                            serde_json::Value::String(error_msg),
                        );
                        debug_info.insert(
                            "action".to_string(),
                            serde_json::Value::String(payload.action.clone()),
                        );
                        debug_info.insert(
                            "execution_time_ms".to_string(),
                            serde_json::Value::Number(
                                serde_json::Number::from_f64(execution_time).unwrap(),
                            ),
                        );
                        details = Some(debug_info);
                    }

                    let response = ErrorResponse {
                        status: "error".to_string(),
                        error: ErrorDetails {
                            code: "EXECUTION_ERROR".to_string(),
                            message,
                            query: if is_debug { query } else { None },
                            bindings: if is_debug { bindings } else { None },
                            details,
                            sql_state: None,
                        },
                    };
                    eprintln!("{}", serde_json::to_string(&response).unwrap());
                }
            }
        }
        Err(e) => {
            let response = ErrorResponse {
                status: "error".to_string(),
                error: ErrorDetails {
                    code: "INVALID_JSON".to_string(),
                    message: format!("Failed to parse JSON input: {}", e),
                    query: None,
                    bindings: None,
                    details: None,
                    sql_state: None,
                },
            };
            eprintln!("{}", serde_json::to_string(&response).unwrap());
        }
    }
}

/// Valida si una operación está permitida bajo el estado freeze actual
#[allow(dead_code)]
fn validate_freeze_operation(
    operation: &str,
    freeze_state: &FreezeState,
    model_class: Option<&str>,
) -> Result<(), String> {
    if !is_ddl_operation(operation) {
        return Ok(()); // No es DDL, permitir
    }

    // Verificar freeze global
    if freeze_state.global_frozen {
        log_error_msg(&format!(
            "DDL operation '{}' blocked by global freeze mode",
            operation
        ));
        return Err(format!(
            "Operation '{}' blocked by global freeze mode. DDL operations are not allowed when freeze mode is active.",
            operation
        ));
    }

    // Verificar freeze por modelo
    if let Some(model) = model_class {
        if *freeze_state.frozen_models.get(model).unwrap_or(&false) {
            log_error_msg(&format!(
                "DDL operation '{}' blocked by model '{}' freeze mode",
                operation, model
            ));
            return Err(format!(
                "Operation '{}' blocked by model '{}' freeze mode. DDL operations are not allowed when this model is frozen.",
                operation, model
            ));
        }
    }

    Ok(())
}

/// Determina si una operación es de tipo DDL (Data Definition Language)
#[allow(dead_code)]
fn is_ddl_operation(operation: &str) -> bool {
    let ddl_operations = [
        "createTable",
        "dropTable",
        "alterTable",
        "addColumn",
        "dropColumn",
        "modifyColumn",
        "renameColumn",
        "addIndex",
        "dropIndex",
        "addForeignKey",
        "dropForeignKey",
        "createIndex",
        "renameTable",
        "truncateTable",
        "create_table",
        "drop_table",
        "alter_table",
        "add_column",
        "drop_column",
        "modify_column",
        "rename_column",
        "add_index",
        "drop_index",
        "create_index",
        "add_foreign_key",
        "drop_foreign_key",
        "rename_table",
        "truncate_table",
        // También considerar consultas SQL raw que modifiquen esquema
        "CREATE",
        "DROP",
        "ALTER",
        "TRUNCATE",
    ];

    let operation_upper = operation.to_uppercase();
    ddl_operations
        .iter()
        .any(|ddl| operation_upper.contains(&ddl.to_uppercase()))
}

/// Valida consultas SQL raw para detectar operaciones DDL
fn validate_raw_query_freeze(query: &str, freeze_state: &FreezeState) -> Result<(), String> {
    let query_upper = query.trim().to_uppercase();

    // Lista de comandos DDL que deben ser bloqueados en modo freeze
    let ddl_commands = [
        "CREATE TABLE",
        "DROP TABLE",
        "ALTER TABLE",
        "TRUNCATE TABLE",
        "CREATE INDEX",
        "DROP INDEX",
        "CREATE SCHEMA",
        "DROP SCHEMA",
        "CREATE DATABASE",
        "DROP DATABASE",
        "CREATE VIEW",
        "DROP VIEW",
        "CREATE PROCEDURE",
        "DROP PROCEDURE",
        "CREATE FUNCTION",
        "DROP FUNCTION",
        "CREATE TRIGGER",
        "DROP TRIGGER",
    ];

    // Verificar si es una operación de creación automática de columnas
    // Las operaciones automáticas están permitidas incluso en modo freeze
    let is_auto_column_creation = query_upper.contains("ADD COLUMN")
        && query_upper.starts_with("ALTER TABLE")
        && !freeze_state.global_frozen; // Solo si no está globalmente congelado

    if is_auto_column_creation {
        // Permitir creación automática de columnas cuando freeze está desactivado
        return Ok(());
    }

    for ddl_cmd in &ddl_commands {
        if query_upper.starts_with(ddl_cmd) && freeze_state.global_frozen {
            log_error_msg(&format!(
                "DDL query '{}' blocked by global freeze mode",
                ddl_cmd
            ));
            return Err(format!(
                "DDL query '{}' blocked by global freeze mode. Schema-modifying operations are not allowed when freeze mode is active.",
                ddl_cmd
            ));
        }
    }

    Ok(())
}

async fn handle_query_action(
    connection: &ConnectionManager,
    params: &serde_json::Value,
    _freeze_state: &FreezeState,
) -> Result<serde_json::Value, (String, Option<String>, Option<Vec<serde_json::Value>>)> {
    let mut query_params: QueryParameters =
        serde_json::from_value(params.clone()).map_err(|e| {
            (
                format!("Failed to deserialize query parameters: {}", e),
                None,
                None,
            )
        })?;

    // If the action is one of the write operations, set it as the method.
    if let Some(action_str) = params.get("action").and_then(|a| a.as_str()) {
        if ["insert", "insertGetId", "update", "delete"].contains(&action_str) {
            query_params.method = action_str.to_string();
        }
    }

    let mut query_builder = QueryBuilder::new(&query_params.table);

    if !query_params.select.is_empty() {
        query_builder.selects = query_params.select;
    }

    for where_clause in query_params.wheres {
        log_debug_msg(&format!(
            "WHERE clause: column={}, operator={}, value={:?}, conjunction={}",
            where_clause.column,
            where_clause.operator,
            where_clause.value,
            where_clause.conjunction
        ));
        query_builder.wheres.push((
            where_clause.column,
            where_clause.operator,
            where_clause.value,
            where_clause.conjunction,
        ));
    }

    for join_clause in query_params.joins {
        // Map PHP join types to Rust join types
        let rust_join_type = match join_clause.join_type.to_lowercase().as_str() {
            "inner" => "INNER",
            "left" => "LEFT",
            "right" => "RIGHT",
            "full_outer" => "FULL OUTER",
            "cross" => "CROSS",
            _ => "INNER", // Default to INNER for unknown types
        };

        // Check if this is a subquery join
        if let Some(subquery_sql) = join_clause.subquery {
            if let Some(alias) = join_clause.alias {
                // Use the join_sub method for subquery joins
                let subquery_bindings = join_clause.subquery_bindings.unwrap_or_default();
                query_builder = query_builder.join_sub(
                    (subquery_sql, subquery_bindings),
                    &alias,
                    &join_clause.first_col,
                    &join_clause.operator,
                    &join_clause.second_col,
                );
            } else {
                return Err(("Subquery joins require an alias".to_string(), None, None));
            }
        } else {
            // Regular table join
            query_builder.joins.push((
                join_clause.table,
                join_clause.first_col,
                join_clause.operator,
                join_clause.second_col,
                rust_join_type.to_string(),
            ));
        }
    }

    if let Some(order) = query_params.order_by.first() {
        query_builder.order = Some((order.column.clone(), order.direction.clone()));
    }

    if let Some(limit) = query_params.limit {
        query_builder.limit = Some(limit);
    }
    if let Some(offset) = query_params.offset {
        query_builder.offset = Some(offset);
    }

    if !query_params.group_by.is_empty() {
        query_builder.group_by = query_params.group_by;
    }

    for having in query_params.having {
        query_builder.havings.push((
            having.column,
            having.operator,
            having.value,
            "AND".to_string(), // Asumiendo AND por ahora, se puede mejorar
        ));
    }

    if !query_params.with.is_empty() {
        query_builder.with = query_params.with;
    }

    let mut insert_data_ref = None;
    if query_params.method == "insert" || query_params.method == "insertGetId" {
        if let Some(data) = &query_params.data {
            query_builder.insert_data = Some(data.clone());
            insert_data_ref = Some(data.clone());
        }
    }

    let table_name = query_builder.table.clone();

    let (sql, sql_params) = query_builder.build_sql_with_method(&query_params.method);

    // Debug SQL y parámetros
    log_debug_msg(&format!("METHOD: {}", query_params.method));
    log_debug_msg(&format!("Generated SQL: {}", sql));
    log_debug_msg(&format!("SQL Parameters: {:?}", sql_params));

    match query_params.method.as_str() {
        "insertMany" => {
            // Debug: Log the entire params structure
            log_debug_msg(&format!(
                "insertMany - Full params: {}",
                serde_json::to_string_pretty(params).unwrap_or("Failed to serialize".to_string())
            ));

            // First try to get records from the root level (new batch format)
            let records = if let Some(records_value) = params.get("records") {
                log_debug_msg(&format!(
                    "insertMany - Found records at root level, type: {}",
                    if records_value.is_array() {
                        "array"
                    } else {
                        "not array"
                    }
                ));
                records_value.as_array().ok_or((
                    "insertMany requires records array".to_string(),
                    None,
                    None,
                ))?
            } else {
                log_debug_msg("insertMany - Records not found at root level, trying fallback");
                // Fallback to old format if not found at root
                query_params
                    .data
                    .as_ref()
                    .and_then(|d| d.get("records"))
                    .and_then(|r| r.as_array())
                    .ok_or(("insertMany requires records array".to_string(), None, None))?
            };

            let batch_size = if let Some(batch_size_value) = params.get("batch_size") {
                batch_size_value.as_i64().unwrap_or(1000) as usize
            } else {
                query_params
                    .data
                    .as_ref()
                    .and_then(|d| d.get("batch_size"))
                    .and_then(|b| b.as_i64())
                    .unwrap_or(1000) as usize
            };

            handle_insert_many(connection, &table_name, records, batch_size).await
        }
        "updateMany" => {
            // First try to get data from the root level (new batch format)
            let update_data = if let Some(data_value) = params.get("data") {
                data_value.as_object().ok_or((
                    "updateMany requires data object".to_string(),
                    None,
                    None,
                ))?
            } else {
                // Fallback to old format if not found at root
                query_params
                    .data
                    .as_ref()
                    .and_then(|d| d.get("data"))
                    .and_then(|d| d.as_object())
                    .ok_or(("updateMany requires data object".to_string(), None, None))?
            };

            let max_records = if let Some(max_records_value) = params.get("max_records") {
                max_records_value.as_i64().unwrap_or(10000)
            } else {
                query_params
                    .data
                    .as_ref()
                    .and_then(|d| d.get("max_records"))
                    .and_then(|m| m.as_i64())
                    .unwrap_or(10000)
            };

            handle_update_many(connection, &query_builder, update_data, max_records).await
        }
        "deleteMany" => {
            let max_records = if let Some(max_records_value) = params.get("max_records") {
                max_records_value.as_i64().unwrap_or(10000)
            } else {
                query_params
                    .data
                    .as_ref()
                    .and_then(|d| d.get("max_records"))
                    .and_then(|m| m.as_i64())
                    .unwrap_or(10000)
            };

            handle_delete_many(connection, &query_builder, max_records).await
        }
        "upsertMany" => {
            // First try to get records from the root level (new batch format)
            let records = if let Some(records_value) = params.get("records") {
                records_value.as_array().ok_or((
                    "upsertMany requires records array".to_string(),
                    None,
                    None,
                ))?
            } else {
                // Fallback to old format if not found at root
                query_params
                    .data
                    .as_ref()
                    .and_then(|d| d.get("records"))
                    .and_then(|r| r.as_array())
                    .ok_or(("upsertMany requires records array".to_string(), None, None))?
            };

            let unique_keys = if let Some(unique_keys_value) = params.get("unique_keys") {
                unique_keys_value.as_array().ok_or((
                    "upsertMany requires unique_keys array".to_string(),
                    None,
                    None,
                ))?
            } else {
                query_params
                    .data
                    .as_ref()
                    .and_then(|d| d.get("unique_keys"))
                    .and_then(|k| k.as_array())
                    .ok_or((
                        "upsertMany requires unique_keys array".to_string(),
                        None,
                        None,
                    ))?
            };

            // Validar unique_keys antes de continuar
            for unique_key_value in unique_keys {
                if let Some(unique_key_str) = unique_key_value.as_str() {
                    if utils::clean_column_name(unique_key_str).is_err() {
                        return Err(("Invalid unique key name detected".to_string(), None, None));
                    }
                }
            }

            let update_columns = if let Some(update_columns_value) = params.get("update_columns") {
                update_columns_value
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>()
            } else {
                query_params
                    .data
                    .as_ref()
                    .and_then(|d| d.get("update_columns"))
                    .and_then(|c| c.as_array())
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>()
            };

            // Validar update_columns antes de continuar
            for update_col in &update_columns {
                if utils::clean_column_name(update_col).is_err() {
                    return Err((
                        "Invalid update column name detected".to_string(),
                        None,
                        None,
                    ));
                }
            }

            let batch_size = if let Some(batch_size_value) = params.get("batch_size") {
                batch_size_value.as_i64().unwrap_or(1000) as usize
            } else {
                query_params
                    .data
                    .as_ref()
                    .and_then(|d| d.get("batch_size"))
                    .and_then(|b| b.as_i64())
                    .unwrap_or(1000) as usize
            };

            handle_upsert_many(
                connection,
                &table_name,
                records,
                unique_keys,
                update_columns,
                batch_size,
            )
            .await
        }
        "get" | "first" => {
            // Generar clave de caché para consultas SELECT
            let cache_key = format!(
                "query:{}:{}",
                sql,
                serde_json::to_string(&sql_params).unwrap_or_default()
            );

            // Intentar obtener del caché primero
            let main_results = if let Some(cached_result) = cache::get_cached_query(&cache_key) {
                log_debug_msg(&format!("Cache HIT for query: {}", sql));
                serde_json::from_str(&cached_result).unwrap_or_else(|_| {
                    log_debug_msg("Failed to deserialize cached result, executing query");
                    Vec::new()
                })
            } else {
                log_debug_msg(&format!("Cache MISS for query: {}", sql));
                let results = connection
                    .execute_raw(&sql, sql_params.clone())
                    .await
                    .map_err(|e| {
                        (
                            format!("Query execution failed: {}", e),
                            Some(sql.to_string()),
                            Some(sql_params.clone()),
                        )
                    })?;

                // Almacenar en caché solo si no hay relaciones (eager loading)
                if query_builder.with.is_empty() {
                    let cache_value = serde_json::to_string(&results).unwrap_or_default();
                    cache::cache_query(&cache_key, &cache_value);
                    log_debug_msg(&format!("Cached query result with key: {}", cache_key));
                }

                results
            };

            // Debug resultados
            log_debug_msg(&format!("Query results count: {}", main_results.len()));
            if !main_results.is_empty() {
                log_debug_msg(&format!("First result: {:?}", main_results[0]));
            }

            if main_results.is_empty() {
                return Ok(serde_json::to_value(main_results).unwrap());
            }

            let mut final_results = main_results.clone();

            // Eager loading
            for relation in &query_builder.with {
                if let (Some(foreign_key), Some(owner_key)) =
                    (&relation.foreign_key, &relation.owner_key)
                {
                    // Para BelongsTo: obtener los valores de foreign_key de los resultados principales
                    // y buscar en la tabla relacionada por owner_key (normalmente 'id')
                    let parent_ids: Vec<serde_json::Value> = final_results
                        .iter()
                        .filter_map(|row| row.get(foreign_key).cloned())
                        .collect();

                    if parent_ids.is_empty() {
                        continue;
                    }

                    // Create placeholders for IN clause
                    let placeholders = vec!["?"; parent_ids.len()].join(", ");
                    let relation_sql = format!(
                        "SELECT * FROM {} WHERE {} IN ({})",
                        relation.related_table, owner_key, placeholders
                    );
                    let relation_rows = connection
                        .execute_raw(&relation_sql, parent_ids)
                        .await
                        .map_err(|e| {
                            (
                                format!("Eager loading failed for {}: {}", relation.name, e),
                                Some(relation_sql),
                                None,
                            )
                        })?;

                    let mut relation_map: HashMap<String, Vec<HashMap<String, serde_json::Value>>> =
                        HashMap::new();
                    for row in relation_rows {
                        if let Some(key_val) = row.get(owner_key) {
                            let key = key_val.to_string().trim_matches('"').to_string();
                            relation_map.entry(key).or_default().push(row.clone());
                        }
                    }

                    for result in &mut final_results {
                        if let Some(local_id_val) = result.get(foreign_key) {
                            let local_id = local_id_val.to_string().trim_matches('"').to_string();
                            if let Some(related_data) = relation_map.get(&local_id) {
                                result.insert(
                                    relation.name.clone(),
                                    serde_json::to_value(related_data.first()).unwrap(),
                                );
                            }
                        }
                    }
                } else if let (Some(foreign_key), Some(local_key)) =
                    (&relation.foreign_key, &relation.local_key)
                {
                    let parent_ids: Vec<serde_json::Value> = final_results
                        .iter()
                        .filter_map(|row| row.get(local_key).cloned())
                        .collect();

                    if parent_ids.is_empty() {
                        continue;
                    }

                    // Create placeholders for IN clause
                    let placeholders = vec!["?"; parent_ids.len()].join(", ");
                    let relation_sql = format!(
                        "SELECT * FROM {} WHERE {} IN ({})",
                        relation.related_table, foreign_key, placeholders
                    );
                    let relation_rows = connection
                        .execute_raw(&relation_sql, parent_ids)
                        .await
                        .map_err(|e| {
                            (
                                format!("Eager loading failed for {}: {}", relation.name, e),
                                Some(relation_sql),
                                None,
                            )
                        })?;

                    let mut relation_map: HashMap<String, Vec<HashMap<String, serde_json::Value>>> =
                        HashMap::new();
                    for row in relation_rows {
                        if let Some(key_val) = row.get(foreign_key) {
                            let key = key_val.to_string().trim_matches('"').to_string();
                            relation_map.entry(key).or_default().push(row.clone());
                        }
                    }

                    for result in &mut final_results {
                        if let Some(local_id_val) = result.get(local_key) {
                            let local_id = local_id_val.to_string().trim_matches('"').to_string();
                            if let Some(related_data) = relation_map.get(&local_id) {
                                result.insert(
                                    relation.name.clone(),
                                    serde_json::to_value(related_data).unwrap(),
                                );
                            }
                        }
                    }
                }
            }

            if query_params.method == "first" {
                Ok(serde_json::to_value(final_results.into_iter().next()).unwrap())
            } else {
                Ok(serde_json::to_value(final_results).unwrap())
            }
        }
        "count" => {
            let count_sql = sql.replacen("SELECT *", "SELECT COUNT(*) as count", 1);
            let count_sql = if count_sql.contains("ORDER BY") {
                count_sql
                    .split(" ORDER BY")
                    .next()
                    .unwrap_or(&count_sql)
                    .to_string()
            } else {
                count_sql
            };

            let rows = connection
                .execute_raw(&count_sql, sql_params.clone())
                .await
                .map_err(|e| {
                    (
                        format!("Count query failed: {}", e),
                        Some(count_sql.clone()),
                        Some(sql_params.clone()),
                    )
                })?;
            let count = rows
                .first()
                .and_then(|row| row.get("count"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            Ok(serde_json::Value::Number(serde_json::Number::from(count)))
        }
        "insert" => {
            if let Some(insert_data) = insert_data_ref {
                let columns: Vec<String> = insert_data.keys().cloned().collect();
                let values: Vec<String> = columns.iter().map(|_| "?".to_string()).collect();
                let insert_sql = format!(
                    "INSERT INTO {} ({}) VALUES ({})",
                    table_name,
                    columns.join(", "),
                    values.join(", ")
                );

                let insert_params: Vec<serde_json::Value> = columns
                    .iter()
                    .map(|col| insert_data.get(col).unwrap().clone())
                    .collect();

                connection
                    .execute_raw(&insert_sql, insert_params.clone())
                    .await
                    .map_err(|e| {
                        (
                            format!("Insert query failed: {}", e),
                            Some(insert_sql.clone()),
                            Some(insert_params.clone()),
                        )
                    })?;

                // Invalidar caché para esta tabla después de INSERT
                cache::invalidate_cache_for_table(&table_name);
                log_debug_msg(&format!("Invalidated cache for table: {}", table_name));

                Ok(serde_json::json!({"status": "Insert successful", "rows_affected": 1}))
            } else {
                Err(("Insert data is missing".to_string(), None, None))
            }
        }
        "insertGetId" => {
            if let Some(insert_data) = insert_data_ref {
                let columns: Vec<String> = insert_data.keys().cloned().collect();
                let values: Vec<String> = columns.iter().map(|_| "?".to_string()).collect();
                let insert_sql = format!(
                    "INSERT INTO {} ({}) VALUES ({})",
                    table_name,
                    columns.join(", "),
                    values.join(", ")
                );

                let insert_params: Vec<serde_json::Value> = columns
                    .iter()
                    .map(|col| insert_data.get(col).unwrap().clone())
                    .collect();

                connection
                    .execute_raw(&insert_sql, insert_params.clone())
                    .await
                    .map_err(|e| {
                        (
                            format!("Insert query failed: {}", e),
                            Some(insert_sql.clone()),
                            Some(insert_params.clone()),
                        )
                    })?;

                let last_id_sql = format!("SELECT MAX(id) as id FROM {}", table_name);
                let last_id_rows =
                    connection
                        .execute_raw(&last_id_sql, vec![])
                        .await
                        .map_err(|e| {
                            (
                                format!("Failed to get last insert ID: {}", e),
                                Some(last_id_sql.clone()),
                                None,
                            )
                        })?;

                let last_id = last_id_rows
                    .first()
                    .and_then(|row| row.get("id"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);

                Ok(serde_json::Value::Number(serde_json::Number::from(last_id)))
            } else {
                Err(("Insert data is missing".to_string(), None, None))
            }
        }
        "exists" => {
            let exists_sql = format!("SELECT EXISTS({}) as exists_result", sql);
            let rows = connection
                .execute_raw(&exists_sql, sql_params.clone())
                .await
                .map_err(|e| {
                    (
                        format!("Exists query failed: {}", e),
                        Some(exists_sql.clone()),
                        Some(sql_params.clone()),
                    )
                })?;
            let exists = rows
                .first()
                .and_then(|row| row.get("exists_result"))
                .map(|v| {
                    if let Some(num) = v.as_i64() {
                        num != 0
                    } else {
                        v.as_bool().unwrap_or_default()
                    }
                })
                .unwrap_or(false);
            Ok(serde_json::Value::Bool(exists))
        }
        "update" => {
            if let Some(update_data) = query_params.data {
                let mut set_clauses = Vec::new();
                let mut update_params = Vec::new();

                for (key, value) in update_data {
                    set_clauses.push(format!("{} = ?", key));
                    update_params.push(value.clone());
                }

                let update_sql = if sql.contains("WHERE") {
                    let where_part = sql.split(" WHERE ").nth(1).unwrap_or("");
                    let where_clause = where_part.split(" ORDER BY").next().unwrap_or(where_part);
                    format!(
                        "UPDATE {} SET {} WHERE {}",
                        table_name,
                        set_clauses.join(", "),
                        where_clause
                    )
                } else {
                    format!("UPDATE {} SET {}", table_name, set_clauses.join(", "))
                };

                update_params.extend(sql_params.clone());

                let rows_affected = connection
                    .execute_write(&update_sql, update_params.clone())
                    .await
                    .map_err(|e| {
                        (
                            format!("Update query failed: {}", e),
                            Some(update_sql.clone()),
                            Some(update_params.clone()),
                        )
                    })?;

                // Invalidar caché para esta tabla después de UPDATE
                cache::invalidate_cache_for_table(&table_name);
                log_debug_msg(&format!("Invalidated cache for table: {}", table_name));

                Ok(serde_json::Value::Number(serde_json::Number::from(
                    rows_affected,
                )))
            } else {
                Err(("Update data is missing".to_string(), None, None))
            }
        }
        "delete" => {
            let delete_sql = if sql.contains("WHERE") {
                let where_part = sql.split(" WHERE ").nth(1).unwrap_or("");
                let where_clause = where_part.split(" ORDER BY").next().unwrap_or(where_part);
                format!("DELETE FROM {} WHERE {}", table_name, where_clause)
            } else {
                format!("DELETE FROM {}", table_name)
            };

            let rows_affected = connection
                .execute_write(&delete_sql, sql_params.clone())
                .await
                .map_err(|e| {
                    (
                        format!("Delete query failed: {}", e),
                        Some(delete_sql.clone()),
                        Some(sql_params.clone()),
                    )
                })?;

            // Invalidar caché para esta tabla después de DELETE
            cache::invalidate_cache_for_table(&table_name);
            log_debug_msg(&format!("Invalidated cache for table: {}", table_name));

            Ok(serde_json::Value::Number(serde_json::Number::from(
                rows_affected,
            )))
        }
        _ => Err((
            format!("Unsupported method: {}", query_params.method),
            Some(sql.to_string()),
            Some(sql_params),
        )),
    }
}

async fn handle_schema_action(
    connection: &ConnectionManager,
    params: &serde_json::Value,
    _freeze_state: &FreezeState,
) -> Result<serde_json::Value, String> {
    let subject = params
        .get("subject")
        .and_then(|v| v.as_str())
        .ok_or("Subject is required for schema action")?;

    let inspector = SchemaInspector::new(connection);

    match subject {
        "tables" => {
            let tables = inspector
                .get_tables()
                .await
                .map_err(|e| format!("Failed to get tables: {}", e))?;
            Ok(serde_json::to_value(tables).unwrap())
        }
        "columns" => {
            let table_name = params
                .get("table_name")
                .and_then(|v| v.as_str())
                .ok_or("Table name is required for columns subject")?;
            let columns = inspector
                .get_columns(table_name)
                .await
                .map_err(|e| format!("Failed to get columns: {}", e))?;
            Ok(serde_json::to_value(columns).unwrap())
        }
        "primaryKey" => {
            let table_name = params
                .get("table_name")
                .and_then(|v| v.as_str())
                .ok_or("Table name is required for primaryKey subject")?;
            let pk = inspector
                .get_primary_key(table_name)
                .await
                .map_err(|e| format!("Failed to get primary key: {}", e))?;
            Ok(serde_json::to_value(pk).unwrap())
        }
        "indexes" => {
            let table_name = params
                .get("table_name")
                .and_then(|v| v.as_str())
                .ok_or("Table name is required for indexes subject")?;
            let indexes = inspector
                .get_indexes(table_name)
                .await
                .map_err(|e| format!("Failed to get indexes: {}", e))?;
            Ok(serde_json::to_value(indexes).unwrap())
        }
        "foreignKeys" => {
            let table_name = params
                .get("table_name")
                .and_then(|v| v.as_str())
                .ok_or("Table name is required for foreignKeys subject")?;
            let fks = inspector
                .get_foreign_keys(table_name)
                .await
                .map_err(|e| format!("Failed to get foreign keys: {}", e))?;
            Ok(serde_json::to_value(fks).unwrap())
        }
        "validationSchema" => {
            let table_name = params
                .get("table_name")
                .and_then(|v| v.as_str())
                .ok_or("Table name is required for validationSchema subject")?;
            let columns = inspector
                .get_columns(table_name)
                .await
                .map_err(|e| format!("Failed to get validation schema: {}", e))?;

            // Crear el esquema de validación con solo la información relevante
            let validation_schema: std::collections::HashMap<String, serde_json::Value> = columns
                .into_iter()
                .map(|col| {
                    (
                        col.name.clone(),
                        serde_json::json!({
                            "data_type": col.data_type,
                            "is_required": col.is_required,
                            "is_nullable": col.is_nullable,
                            "max_length": col.max_length,
                            "validation_rules": col.validation_rules,
                            "is_primary_key": col.is_primary_key,
                            "is_auto_increment": col.is_auto_increment,
                            "default_value": col.default_value
                        }),
                    )
                })
                .collect();

            Ok(serde_json::to_value(validation_schema).unwrap())
        }
        _ => Err(format!("Unknown schema subject: {}", subject)),
    }
}

async fn handle_raw_action(
    connection: &ConnectionManager,
    params: &serde_json::Value,
    freeze_state: &FreezeState,
) -> Result<serde_json::Value, (String, Option<String>, Option<Vec<serde_json::Value>>)> {
    let query = params.get("query").and_then(|v| v.as_str()).ok_or((
        "Query is required for raw action".to_string(),
        None,
        None,
    ))?;

    let bindings = params
        .get("bindings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // Validar freeze para consultas DDL
    if let Err(freeze_error) = validate_raw_query_freeze(query, freeze_state) {
        return Err((
            freeze_error,
            Some(query.to_string()),
            Some(bindings.clone()),
        ));
    }

    let query_upper = query.trim().to_uppercase();

    // Para transacciones, necesitamos manejar el estado de autocommit
    if query_upper.starts_with("BEGIN") || query_upper.starts_with("START TRANSACTION") {
        // Primero, deshabilitar autocommit
        if let Err(e) = connection.execute_unprepared("SET autocommit = 0").await {
            return Err((
                format!("Failed to disable autocommit: {}", e),
                Some("SET autocommit = 0".to_string()),
                None,
            ));
        }
        // Luego iniciar la transacción
        connection
            .execute_unprepared("START TRANSACTION")
            .await
            .map(|rows_affected| serde_json::json!({ "rows_affected": rows_affected }))
            .map_err(|e| {
                (
                    format!("Transaction start failed: {}", e),
                    Some("START TRANSACTION".to_string()),
                    None,
                )
            })
    } else if query_upper.starts_with("COMMIT") {
        // Hacer commit y rehabilitar autocommit
        let commit_result = connection.execute_unprepared("COMMIT").await;
        let _ = connection.execute_unprepared("SET autocommit = 1").await; // Siempre rehabilitar
        commit_result
            .map(|rows_affected| serde_json::json!({ "rows_affected": rows_affected }))
            .map_err(|e| {
                (
                    format!("Transaction commit failed: {}", e),
                    Some("COMMIT".to_string()),
                    None,
                )
            })
    } else if query_upper.starts_with("ROLLBACK") {
        // Hacer rollback y rehabilitar autocommit
        let rollback_result = connection.execute_unprepared("ROLLBACK").await;
        let _ = connection.execute_unprepared("SET autocommit = 1").await; // Siempre rehabilitar
        rollback_result
            .map(|rows_affected| serde_json::json!({ "rows_affected": rows_affected }))
            .map_err(|e| {
                (
                    format!("Transaction rollback failed: {}", e),
                    Some("ROLLBACK".to_string()),
                    None,
                )
            })
    } else {
        let needs_unprepared = query_upper.starts_with("SET FOREIGN_KEY_CHECKS")
            || query_upper.starts_with("TRUNCATE")
            || query_upper.starts_with("DROP TABLE")
            || query_upper.starts_with("CREATE TABLE")
            || query_upper.starts_with("ALTER TABLE");

        if needs_unprepared || bindings.is_empty() {
            connection
                .execute_unprepared(query)
                .await
                .map(|rows_affected| serde_json::json!({ "rows_affected": rows_affected }))
                .map_err(|e| {
                    (
                        format!("Unprepared raw query execution failed: {}", e),
                        Some(query.to_string()),
                        None,
                    )
                })
        } else {
            let rows = connection
                .execute_raw(query, bindings.clone())
                .await
                .map_err(|e| {
                    (
                        format!("Raw query execution failed: {}", e),
                        Some(query.to_string()),
                        Some(bindings.clone()),
                    )
                })?;
            Ok(serde_json::to_value(rows).unwrap())
        }
    }
}

fn handle_cache_action(params: &serde_json::Value) -> Result<serde_json::Value, String> {
    let action = params
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or("Action is required for cache")?;

    match action {
        "enable" => {
            cache::enable_cache();
            Ok(serde_json::Value::String("Cache enabled".to_string()))
        }
        "disable" => {
            cache::disable_cache();
            Ok(serde_json::Value::String("Cache disabled".to_string()))
        }
        "clear" => {
            cache::clear_cache();
            Ok(serde_json::Value::String("Cache cleared".to_string()))
        }
        "cleanup" => {
            cache::cleanup_expired_entries();
            Ok(serde_json::Value::String(
                "Expired entries cleaned up".to_string(),
            ))
        }
        "status" => {
            let status = cache::cache_status();
            Ok(serde_json::Value::Number(serde_json::Number::from(status)))
        }
        "stats" => Ok(cache::cache_stats()),
        "config" => {
            let max_size = params
                .get("max_size")
                .and_then(|v| v.as_u64())
                .unwrap_or(1000) as usize;
            let ttl_secs = params
                .get("ttl_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(300);
            cache::set_cache_config(max_size, ttl_secs);
            Ok(serde_json::json!({
                "message": "Cache configuration updated",
                "max_size": max_size,
                "ttl_secs": ttl_secs
            }))
        }
        "invalidate" => {
            if let Some(table) = params.get("table").and_then(|v| v.as_str()) {
                cache::invalidate_cache_for_table(table);
                Ok(serde_json::Value::String(format!(
                    "Cache invalidated for table: {}",
                    table
                )))
            } else if let Some(pattern) = params.get("pattern").and_then(|v| v.as_str()) {
                cache::invalidate_cache_by_pattern(pattern);
                Ok(serde_json::Value::String(format!(
                    "Cache invalidated for pattern: {}",
                    pattern
                )))
            } else {
                Err(
                    "Either 'table' or 'pattern' parameter is required for invalidate action"
                        .to_string(),
                )
            }
        }
        _ => Err(format!("Unknown cache action: {}", action)),
    }
}

//======================================================================
// BATCH OPERATIONS HANDLERS - Tarea 2.2
//======================================================================

/**
 * Manejo de insertMany - Inserta múltiples registros en lotes optimizados
 */
async fn handle_insert_many(
    connection: &ConnectionManager,
    table_name: &str,
    records: &[serde_json::Value],
    batch_size: usize,
) -> Result<serde_json::Value, (String, Option<String>, Option<Vec<serde_json::Value>>)> {
    if records.is_empty() {
        return Err(("No records provided for insertion".to_string(), None, None));
    }

    // Validar la estructura del primer registro para obtener las columnas
    let first_record = records.first().unwrap();
    log_debug_msg(&format!("insertMany - First record: {:?}", first_record));

    let first_obj = first_record.as_object().ok_or((
        "First record must be an object".to_string(),
        None,
        None,
    ))?;

    if first_obj.is_empty() {
        return Err(("Records cannot be empty".to_string(), None, None));
    }

    let columns: Vec<String> = first_obj.keys().cloned().collect();
    let mut total_inserted = 0;
    let mut batches_processed = 0;
    let mut errors = Vec::new();

    // Procesar en lotes
    for chunk in records.chunks(batch_size) {
        // Construir el SQL de inserción múltiple
        let values_placeholders: Vec<String> = chunk
            .iter()
            .map(|_| format!("({})", vec!["?"; columns.len()].join(", ")))
            .collect();

        let insert_sql = format!(
            "INSERT INTO {} ({}) VALUES {}",
            table_name,
            columns.join(", "),
            values_placeholders.join(", ")
        );

        // Preparar parámetros en el orden correcto
        let mut params = Vec::new();
        for record in chunk {
            let record_obj = record.as_object().ok_or((
                "All records must be objects".to_string(),
                Some(insert_sql.clone()),
                None,
            ))?;

            // Validar que el registro tenga las mismas columnas
            let record_keys: Vec<String> = record_obj.keys().cloned().collect();
            if record_keys != columns {
                return Err((
                    format!(
                        "Record structure mismatch. Expected: [{}], Got: [{}]",
                        columns.join(", "),
                        record_keys.join(", ")
                    ),
                    Some(insert_sql.clone()),
                    None,
                ));
            }

            for column in &columns {
                params.push(record_obj.get(column).unwrap().clone());
            }
        }

        // Ejecutar el lote
        match connection.execute_raw(&insert_sql, params.clone()).await {
            Ok(_) => {
                total_inserted += chunk.len();
                batches_processed += 1;
                log_debug_msg(&format!(
                    "Batch {} completed: {} records inserted",
                    batches_processed,
                    chunk.len()
                ));
            }
            Err(e) => {
                let error_msg = format!("Batch {} failed: {}", batches_processed + 1, e);
                errors.push(error_msg.clone());
                log_debug_msg(&error_msg);

                // En caso de error, podemos decidir si continuar o abortar
                // Por ahora, abortamos para mantener la consistencia
                return Err((
                    format!(
                        "insertMany failed at batch {}: {}. Total inserted before failure: {}",
                        batches_processed + 1,
                        e,
                        total_inserted
                    ),
                    Some(insert_sql),
                    Some(params),
                ));
            }
        }
    }

    Ok(serde_json::json!({
        "total_inserted": total_inserted,
        "batches_processed": batches_processed,
        "batch_size": batch_size,
        "total_records": records.len(),
        "status": "success",
        "errors": errors
    }))
}

/**
 * Manejo de updateMany - Actualiza múltiples registros con condiciones WHERE
 */
async fn handle_update_many(
    connection: &ConnectionManager,
    query_builder: &QueryBuilder,
    update_data: &serde_json::Map<String, serde_json::Value>,
    max_records: i64,
) -> Result<serde_json::Value, (String, Option<String>, Option<Vec<serde_json::Value>>)> {
    if update_data.is_empty() {
        return Err(("No data provided for update".to_string(), None, None));
    }

    if query_builder.wheres.is_empty() {
        return Err((
            "updateMany requires WHERE conditions to prevent accidental mass updates".to_string(),
            None,
            None,
        ));
    }

    // Primero, contar cuántos registros serían afectados
    let (count_sql, count_params) = query_builder.build_sql_with_method("count");
    let count_sql = count_sql.replacen("SELECT *", "SELECT COUNT(*) as count", 1);

    let count_rows = connection
        .execute_raw(&count_sql, count_params.clone())
        .await
        .map_err(|e| {
            (
                format!("Failed to count records for updateMany: {}", e),
                Some(count_sql.clone()),
                Some(count_params.clone()),
            )
        })?;

    let affected_count = count_rows
        .first()
        .and_then(|row| row.get("count"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    // Verificar límite de seguridad
    if affected_count > max_records {
        return Err((
            format!(
                "updateMany would affect {} records, which exceeds the maximum limit of {}. Use a more restrictive WHERE clause or increase max_records.",
                affected_count, max_records
            ),
            Some(count_sql),
            Some(count_params),
        ));
    }

    if affected_count == 0 {
        return Ok(serde_json::json!({
            "rows_affected": 0,
            "status": "success",
            "message": "No records matched the WHERE conditions"
        }));
    }

    // Construir la consulta UPDATE
    let (select_sql, where_params) = query_builder.build_sql_with_method("get");

    let mut set_clauses = Vec::new();
    let mut update_params = Vec::new();

    for (key, value) in update_data {
        set_clauses.push(format!("{} = ?", key));
        update_params.push(value.clone());
    }

    // Extraer la cláusula WHERE del SQL de selección
    let where_clause = if select_sql.contains(" WHERE ") {
        let where_part = select_sql.split(" WHERE ").nth(1).unwrap_or("");
        where_part.split(" ORDER BY").next().unwrap_or(where_part)
    } else {
        ""
    };

    let update_sql = if !where_clause.is_empty() {
        format!(
            "UPDATE {} SET {} WHERE {}",
            query_builder.table,
            set_clauses.join(", "),
            where_clause
        )
    } else {
        return Err((
            "Unable to construct WHERE clause for updateMany".to_string(),
            None,
            None,
        ));
    };

    // Combinar parámetros: primero los de SET, luego los de WHERE
    update_params.extend(where_params);

    // Ejecutar la actualización
    let rows_affected = connection
        .execute_write(&update_sql, update_params.clone())
        .await
        .map_err(|e| {
            (
                format!("updateMany execution failed: {}", e),
                Some(update_sql.clone()),
                Some(update_params.clone()),
            )
        })?;

    log_debug_msg(&format!(
        "updateMany completed: {} rows affected",
        rows_affected
    ));

    Ok(serde_json::json!({
        "rows_affected": rows_affected,
        "expected_count": affected_count,
        "status": "success",
        "update_data": update_data
    }))
}

/**
 * Manejo de deleteMany - Elimina múltiples registros con condiciones WHERE
 */
async fn handle_delete_many(
    connection: &ConnectionManager,
    query_builder: &QueryBuilder,
    max_records: i64,
) -> Result<serde_json::Value, (String, Option<String>, Option<Vec<serde_json::Value>>)> {
    if query_builder.wheres.is_empty() {
        return Err((
            "deleteMany requires WHERE conditions to prevent accidental mass deletions".to_string(),
            None,
            None,
        ));
    }

    // Primero, contar cuántos registros serían eliminados
    let (count_sql, count_params) = query_builder.build_sql_with_method("count");
    let count_sql = count_sql.replacen("SELECT *", "SELECT COUNT(*) as count", 1);

    let count_rows = connection
        .execute_raw(&count_sql, count_params.clone())
        .await
        .map_err(|e| {
            (
                format!("Failed to count records for deleteMany: {}", e),
                Some(count_sql.clone()),
                Some(count_params.clone()),
            )
        })?;

    let affected_count = count_rows
        .first()
        .and_then(|row| row.get("count"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    // Verificar límite de seguridad
    if affected_count > max_records {
        return Err((
            format!(
                "deleteMany would affect {} records, which exceeds the maximum limit of {}. Use a more restrictive WHERE clause or increase max_records.",
                affected_count, max_records
            ),
            Some(count_sql),
            Some(count_params),
        ));
    }

    if affected_count == 0 {
        return Ok(serde_json::json!({
            "rows_affected": 0,
            "status": "success",
            "message": "No records matched the WHERE conditions"
        }));
    }

    // Construir la consulta DELETE
    let (select_sql, delete_params) = query_builder.build_sql_with_method("get");

    // Extraer la cláusula WHERE del SQL de selección
    let where_clause = if select_sql.contains(" WHERE ") {
        let where_part = select_sql.split(" WHERE ").nth(1).unwrap_or("");
        where_part.split(" ORDER BY").next().unwrap_or(where_part)
    } else {
        ""
    };

    let delete_sql = if !where_clause.is_empty() {
        format!("DELETE FROM {} WHERE {}", query_builder.table, where_clause)
    } else {
        return Err((
            "Unable to construct WHERE clause for deleteMany".to_string(),
            None,
            None,
        ));
    };

    // Ejecutar la eliminación
    let rows_affected = connection
        .execute_write(&delete_sql, delete_params.clone())
        .await
        .map_err(|e| {
            (
                format!("deleteMany execution failed: {}", e),
                Some(delete_sql.clone()),
                Some(delete_params.clone()),
            )
        })?;

    log_debug_msg(&format!(
        "deleteMany completed: {} rows affected",
        rows_affected
    ));

    Ok(serde_json::json!({
        "rows_affected": rows_affected,
        "expected_count": affected_count,
        "status": "success"
    }))
}

/**
 * Manejo de upsertMany - INSERT ... ON DUPLICATE KEY UPDATE para múltiples registros
 */
async fn handle_upsert_many(
    connection: &ConnectionManager,
    table_name: &str,
    records: &[serde_json::Value],
    unique_keys: &[serde_json::Value],
    update_columns: Vec<String>,
    batch_size: usize,
) -> Result<serde_json::Value, (String, Option<String>, Option<Vec<serde_json::Value>>)> {
    if records.is_empty() {
        return Err(("No records provided for upsert".to_string(), None, None));
    }

    if unique_keys.is_empty() {
        return Err(("No unique keys provided for upsert".to_string(), None, None));
    }

    // Convertir unique_keys a strings y validar nombres de columnas
    let unique_key_names: Vec<String> = unique_keys
        .iter()
        .filter_map(|v| v.as_str())
        .map(|s| s.to_string())
        .collect();

    if unique_key_names.is_empty() {
        return Err(("Invalid unique keys format".to_string(), None, None));
    }

    // Validar que los nombres de unique keys sean seguros
    for unique_key in &unique_key_names {
        log_debug_msg(&format!("Validating unique key name: '{}'", unique_key));
        if let Err(err) = utils::clean_column_name(unique_key) {
            log_debug_msg(&format!(
                "Unique key '{}' failed validation: {}",
                unique_key, err
            ));
            return Err(("Invalid unique key name detected".to_string(), None, None));
        }
        log_debug_msg(&format!("Unique key '{}' passed validation", unique_key));
    }

    // Validar que los nombres de update_columns sean seguros
    for update_col in &update_columns {
        if utils::clean_column_name(update_col).is_err() {
            return Err((
                "Invalid update column name detected".to_string(),
                None,
                None,
            ));
        }
    }

    // Obtener el driver de base de datos para determinar la sintaxis correcta
    let driver = connection.get_driver();

    // Validar la estructura del primer registro
    let first_record = records.first().unwrap();
    let first_obj = first_record.as_object().ok_or((
        "First record must be an object".to_string(),
        None,
        None,
    ))?;

    let columns: Vec<String> = first_obj.keys().cloned().collect();
    let mut total_processed = 0;
    let mut batches_processed = 0;
    let mut errors = Vec::new();

    // Procesar en lotes
    for chunk in records.chunks(batch_size) {
        let upsert_sql = match driver {
            "mysql" => {
                // MySQL: INSERT ... ON DUPLICATE KEY UPDATE
                let values_placeholders: Vec<String> = chunk
                    .iter()
                    .map(|_| format!("({})", vec!["?"; columns.len()].join(", ")))
                    .collect();

                let update_clause = if update_columns.is_empty() {
                    // Si no se especifican columnas, actualizar todas excepto las únicas
                    columns
                        .iter()
                        .filter(|col| !unique_key_names.contains(col))
                        .map(|col| format!("{} = VALUES({})", col, col))
                        .collect::<Vec<_>>()
                        .join(", ")
                } else {
                    update_columns
                        .iter()
                        .map(|col| format!("{} = VALUES({})", col, col))
                        .collect::<Vec<_>>()
                        .join(", ")
                };

                if update_clause.is_empty() {
                    return Err((
                        "No columns available for update in upsert operation".to_string(),
                        None,
                        None,
                    ));
                }

                format!(
                    "INSERT INTO {} ({}) VALUES {} ON DUPLICATE KEY UPDATE {}",
                    table_name,
                    columns.join(", "),
                    values_placeholders.join(", "),
                    update_clause
                )
            }
            "pgsql" | "postgresql" => {
                // PostgreSQL: INSERT ... ON CONFLICT DO UPDATE
                let values_placeholders: Vec<String> = chunk
                    .iter()
                    .map(|_| format!("({})", vec!["?"; columns.len()].join(", ")))
                    .collect();

                let update_clause = if update_columns.is_empty() {
                    columns
                        .iter()
                        .filter(|col| !unique_key_names.contains(col))
                        .map(|col| format!("{} = EXCLUDED.{}", col, col))
                        .collect::<Vec<_>>()
                        .join(", ")
                } else {
                    update_columns
                        .iter()
                        .map(|col| format!("{} = EXCLUDED.{}", col, col))
                        .collect::<Vec<_>>()
                        .join(", ")
                };

                if update_clause.is_empty() {
                    return Err((
                        "No columns available for update in upsert operation".to_string(),
                        None,
                        None,
                    ));
                }

                format!(
                    "INSERT INTO {} ({}) VALUES {} ON CONFLICT ({}) DO UPDATE SET {}",
                    table_name,
                    columns.join(", "),
                    values_placeholders.join(", "),
                    unique_key_names.join(", "),
                    update_clause
                )
            }
            _ => {
                return Err((
                    format!("Upsert operations not supported for driver: {}", driver),
                    None,
                    None,
                ));
            }
        };

        // Preparar parámetros
        let mut params = Vec::new();
        for record in chunk {
            let record_obj = record.as_object().ok_or((
                "All records must be objects".to_string(),
                Some(upsert_sql.clone()),
                None,
            ))?;

            // Validar que todas las claves únicas estén presentes
            for unique_key in &unique_key_names {
                if !record_obj.contains_key(unique_key) {
                    return Err((
                        format!(
                            "Record at index {} is missing unique key: {}",
                            chunk.iter().position(|r| r == record).unwrap_or(0),
                            unique_key
                        ),
                        Some(upsert_sql.clone()),
                        None,
                    ));
                }
            }

            for column in &columns {
                params.push(record_obj.get(column).unwrap().clone());
            }
        }

        // Ejecutar el lote
        log_debug_msg(&format!("Executing upsert SQL: {}", upsert_sql));
        log_debug_msg(&format!("Parameters: {:?}", params));

        match connection.execute_raw(&upsert_sql, params.clone()).await {
            Ok(_) => {
                total_processed += chunk.len();
                batches_processed += 1;
                log_debug_msg(&format!(
                    "Upsert batch {} completed: {} records processed",
                    batches_processed,
                    chunk.len()
                ));
            }
            Err(e) => {
                let error_msg = format!("Upsert batch {} failed: {}", batches_processed + 1, e);
                errors.push(error_msg.clone());
                log_debug_msg(&error_msg);

                return Err((
                    format!(
                        "upsertMany failed at batch {}: {}. Total processed before failure: {}",
                        batches_processed + 1,
                        e,
                        total_processed
                    ),
                    Some(upsert_sql),
                    Some(params),
                ));
            }
        }
    }

    Ok(serde_json::json!({
        "total_processed": total_processed,
        "batches_processed": batches_processed,
        "batch_size": batch_size,
        "total_records": records.len(),
        "unique_keys": unique_key_names,
        "update_columns": update_columns,
        "status": "success",
        "errors": errors
    }))
}
