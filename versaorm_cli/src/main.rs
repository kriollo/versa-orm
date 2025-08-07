// Permitir estos warnings de Clippy temporalmente mientras refactorizamos
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::unnecessary_to_owned)]
#![allow(clippy::unnecessary_get_then_check)]

use chrono::{Duration, Local, TimeZone, Utc};
use clap::Parser;
use query_planner::{JoinCondition, OrderBy, QueryCondition, QueryOperation, QueryOptimizer};
use serde::{Deserialize, Serialize};
use sqlx::{Column, Row}; // Agregamos Column también
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

/// Genera placeholders apropiados según el tipo de base de datos
fn generate_placeholders(count: usize, driver: &str) -> Vec<String> {
    match driver {
        "postgres" | "postgresql" | "pgsql" => {
            (1..=count).map(|i| format!("${}", i)).collect()
        }
        _ => {
            // MySQL, SQLite, MSSQL usan ?
            vec!["?".to_string(); count]
        }
    }
}

/// Genera placeholders secuenciales comenzando desde un offset específico
fn generate_placeholders_from_offset(count: usize, driver: &str, offset: usize) -> Vec<String> {
    match driver {
        "postgres" | "postgresql" | "pgsql" => {
            (1..=count).map(|i| format!("${}", i + offset)).collect()
        }
        _ => {
            // MySQL, SQLite, MSSQL usan ?
            vec!["?".to_string(); count]
        }
    }
}

/// Convierte placeholders ? a formato específico de la base de datos
fn convert_placeholders(query: &str, driver: &str) -> String {
    utils::convert_placeholders_for_database(query, driver)
}

// Módulos del ORM
mod advanced_sql;
mod cache;
mod connection;
mod database_specific;
mod model;
mod query;
mod query_planner;
mod schema;
mod tests;
mod utils;

use advanced_sql::AdvancedSqlFeatures;
use connection::{ConnectionManager, DatabaseConfig};
use database_specific::DatabaseSpecificFeatures;
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
                "query" | "insert" | "insertGetId" | "update" | "delete" | "replaceInto" => {
                    handle_query_action(&connection_manager, &payload.params, &payload.freeze_state)
                        .await
                }
                "query_plan" => handle_query_plan_action(&mut connection_manager, &payload.params)
                    .await
                    .map_err(|e| (e, None, None)),
                "explain_plan" => handle_explain_plan_action(&payload.params)
                    .await
                    .map_err(|e| (e, None, None)),
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
                "advanced_sql" => handle_advanced_sql_action(&connection_manager, &payload.params).await,
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

    let (sql, sql_params) = query_builder.build_sql_with_method_for_driver(&query_params.method, connection.get_driver());

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
        "replaceInto" => {
            // Handle single record replace (MySQL specific)
            let data = if let Some(data_value) = params.get("data") {
                data_value.as_object().ok_or((
                    "replaceInto requires data object".to_string(),
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
                    .ok_or(("replaceInto requires data object".to_string(), None, None))?
            };

            handle_replace_into(connection, &table_name, data).await
        }
        "replaceIntoMany" => {
            // Handle multiple record replace (MySQL specific)
            let records = if let Some(records_value) = params.get("records") {
                records_value.as_array().ok_or((
                    "replaceIntoMany requires records array".to_string(),
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
                    .ok_or(("replaceIntoMany requires records array".to_string(), None, None))?
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

            handle_replace_into_many(connection, &table_name, records, batch_size).await
        }
        "upsert" => {
            // Handle single record upsert
            let data = if let Some(data_value) = params.get("data") {
                data_value.as_object().ok_or((
                    "upsert requires data object".to_string(),
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
                    .ok_or(("upsert requires data object".to_string(), None, None))?
            };

            let unique_keys = if let Some(unique_keys_value) = params.get("unique_keys") {
                unique_keys_value.as_array().ok_or((
                    "upsert requires unique_keys array".to_string(),
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
                        "upsert requires unique_keys array".to_string(),
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

            handle_upsert(
                connection,
                &table_name,
                data,
                unique_keys,
                update_columns,
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
                    let placeholders = generate_placeholders(parent_ids.len(), connection.get_driver());
                    let relation_sql = format!(
                        "SELECT * FROM {} WHERE {} IN ({})",
                        relation.related_table, owner_key, placeholders.join(", ")
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
                    let placeholders = generate_placeholders(parent_ids.len(), connection.get_driver());
                    let relation_sql = format!(
                        "SELECT * FROM {} WHERE {} IN ({})",
                        relation.related_table, foreign_key, placeholders.join(", ")
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
                let values = generate_placeholders(columns.len(), connection.get_driver());
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
                let values = generate_placeholders(columns.len(), connection.get_driver());
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
                let driver = connection.get_driver();

                for (i, (key, value)) in update_data.iter().enumerate() {
                    let placeholder = match driver {
                        "postgres" | "postgresql" | "pgsql" => format!("${}", i + 1),
                        _ => "?".to_string()
                    };
                    set_clauses.push(format!("{} = {}", key, placeholder));
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
            // Convertir placeholders según el driver de base de datos
            let converted_query = convert_placeholders(query, connection.get_driver());

            let rows = connection
                .execute_raw(&converted_query, bindings.clone())
                .await
                .map_err(|e| {
                    (
                        format!("Raw query execution failed: {}", e),
                        Some(converted_query.clone()),
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
    let (count_sql, count_params) = query_builder.build_sql_with_method_for_driver("count", connection.get_driver());
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
    let (select_sql, where_params) = query_builder.build_sql_with_method_for_driver("get", connection.get_driver());

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
    let (count_sql, count_params) = query_builder.build_sql_with_method_for_driver("count", connection.get_driver());
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
    let (select_sql, delete_params) = query_builder.build_sql_with_method_for_driver("get", connection.get_driver());

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
 * Manejo de upsert - INSERT ... ON DUPLICATE KEY UPDATE para un solo registro
 */
async fn handle_upsert(
    connection: &ConnectionManager,
    table_name: &str,
    data: &serde_json::Map<String, serde_json::Value>,
    unique_keys: &[serde_json::Value],
    update_columns: Vec<String>,
) -> Result<serde_json::Value, (String, Option<String>, Option<Vec<serde_json::Value>>)> {
    if data.is_empty() {
        return Err(("No data provided for upsert".to_string(), None, None));
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
        if let Err(err) = utils::clean_column_name(unique_key) {
            log_debug_msg(&format!(
                "Unique key '{}' failed validation: {}",
                unique_key, err
            ));
            return Err(("Invalid unique key name detected".to_string(), None, None));
        }
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

    // Validar que todas las claves únicas estén presentes en los datos
    for unique_key in &unique_key_names {
        if !data.contains_key(unique_key) {
            return Err((
                format!("Data is missing unique key: {}", unique_key),
                None,
                None,
            ));
        }
    }

    // Obtener el driver de base de datos para determinar la sintaxis correcta
    let driver = connection.get_driver();

    let columns: Vec<String> = data.keys().cloned().collect();

    let upsert_sql = match driver {
        "mysql" => {
            // MySQL: INSERT ... ON DUPLICATE KEY UPDATE
            let values_placeholder = format!("({})", vec!["?"; columns.len()].join(", "));

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
                values_placeholder,
                update_clause
            )
        }
        "postgres" | "postgresql" | "pgsql" => {
            // PostgreSQL: INSERT ... ON CONFLICT DO UPDATE
            let values_placeholder = format!("({})", vec!["?"; columns.len()].join(", "));

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
                values_placeholder,
                unique_key_names.join(", "),
                update_clause
            )
        }
        "sqlite" => {
            // SQLite: INSERT OR REPLACE INTO o INSERT ... ON CONFLICT DO UPDATE
            // Usando REPLACE que es más simple pero puede perder datos relacionados
            let values_placeholder = format!("({})", vec!["?"; columns.len()].join(", "));

            format!(
                "INSERT OR REPLACE INTO {} ({}) VALUES {}",
                table_name,
                columns.join(", "),
                values_placeholder
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

    // Preparar parámetros en el orden correcto
    let params: Vec<serde_json::Value> = columns
        .iter()
        .map(|col| data.get(col).unwrap().clone())
        .collect();

    // Ejecutar la consulta upsert
    log_debug_msg(&format!("Executing upsert SQL: {}", upsert_sql));
    log_debug_msg(&format!("Parameters: {:?}", params));

    match connection.execute_raw(&upsert_sql, params.clone()).await {
        Ok(results) => {
            log_debug_msg("Upsert operation completed successfully");

            // Para upsert individual, intentamos determinar si fue INSERT o UPDATE
            // MySQL devuelve affected_rows: 1 para INSERT, 2 para UPDATE
            // PostgreSQL devuelve 1 para ambos casos
            let operation_type = if driver == "mysql" && results.len() == 2 {
                "updated"
            } else {
                "inserted_or_updated"
            };

            Ok(serde_json::json!({
                "status": "success",
                "operation": operation_type,
                "rows_affected": 1,
                "unique_keys": unique_key_names,
                "update_columns": update_columns,
                "table": table_name
            }))
        }
        Err(e) => {
            let error_msg = format!("Upsert operation failed: {}", e);
            log_debug_msg(&error_msg);
            Err((
                error_msg,
                Some(upsert_sql),
                Some(params),
            ))
        }
    }
}

/**
 * Manejo de replaceInto - REPLACE INTO para un solo registro (MySQL específico)
 */
async fn handle_replace_into(
    connection: &ConnectionManager,
    table_name: &str,
    data: &serde_json::Map<String, serde_json::Value>,
) -> Result<serde_json::Value, (String, Option<String>, Option<Vec<serde_json::Value>>)> {
    if data.is_empty() {
        return Err(("No data provided for replaceInto".to_string(), None, None));
    }

    // Verificar que el driver sea MySQL
    let driver = connection.get_driver();
    if driver != "mysql" {
        return Err((
            format!("REPLACE INTO operations are only supported for MySQL, current driver: {}", driver),
            None,
            None,
        ));
    }

    let columns: Vec<String> = data.keys().cloned().collect();
    let values_placeholder = format!("({})", vec!["?"; columns.len()].join(", "));

    let replace_sql = format!(
        "REPLACE INTO {} ({}) VALUES {}",
        table_name,
        columns.join(", "),
        values_placeholder
    );

    // Preparar parámetros en el orden correcto
    let params: Vec<serde_json::Value> = columns
        .iter()
        .map(|col| data.get(col).unwrap().clone())
        .collect();

    // Ejecutar la consulta REPLACE INTO
    log_debug_msg(&format!("Executing replaceInto SQL: {}", replace_sql));
    log_debug_msg(&format!("Parameters: {:?}", params));

    match connection.execute_raw(&replace_sql, params.clone()).await {
        Ok(_) => {
            log_debug_msg("replaceInto operation completed successfully");

            // Invalidar caché para esta tabla después de REPLACE INTO
            cache::invalidate_cache_for_table(table_name);
            log_debug_msg(&format!("Invalidated cache for table: {}", table_name));

            Ok(serde_json::json!({
                "status": "success",
                "operation": "replaced",
                "rows_affected": 1,
                "table": table_name
            }))
        }
        Err(e) => {
            let error_msg = format!("replaceInto operation failed: {}", e);
            log_debug_msg(&error_msg);
            Err((
                error_msg,
                Some(replace_sql),
                Some(params),
            ))
        }
    }
}

/**
 * Manejo de replaceIntoMany - REPLACE INTO para múltiples registros (MySQL específico)
 */
async fn handle_replace_into_many(
    connection: &ConnectionManager,
    table_name: &str,
    records: &[serde_json::Value],
    batch_size: usize,
) -> Result<serde_json::Value, (String, Option<String>, Option<Vec<serde_json::Value>>)> {
    if records.is_empty() {
        return Err(("No records provided for replaceIntoMany".to_string(), None, None));
    }

    // Verificar que el driver sea MySQL
    let driver = connection.get_driver();
    if driver != "mysql" {
        return Err((
            format!("REPLACE INTO operations are only supported for MySQL, current driver: {}", driver),
            None,
            None,
        ));
    }

    // Validar la estructura del primer registro
    let first_record = records.first().unwrap();
    let first_obj = first_record.as_object().ok_or((
        "First record must be an object".to_string(),
        None,
        None,
    ))?;

    if first_obj.is_empty() {
        return Err(("Records cannot be empty".to_string(), None, None));
    }

    let columns: Vec<String> = first_obj.keys().cloned().collect();
    let mut total_replaced = 0;
    let mut batches_processed = 0;
    let mut errors = Vec::new();

    // Procesar en lotes
    for chunk in records.chunks(batch_size) {
        // Construir el SQL de REPLACE INTO múltiple
        let values_placeholders: Vec<String> = chunk
            .iter()
            .map(|_| format!("({})", vec!["?"; columns.len()].join(", ")))
            .collect();

        let replace_sql = format!(
            "REPLACE INTO {} ({}) VALUES {}",
            table_name,
            columns.join(", "),
            values_placeholders.join(", ")
        );

        // Preparar parámetros en el orden correcto
        let mut params = Vec::new();
        for record in chunk {
            let record_obj = record.as_object().ok_or((
                "All records must be objects".to_string(),
                Some(replace_sql.clone()),
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
                    Some(replace_sql.clone()),
                    None,
                ));
            }

            for column in &columns {
                params.push(record_obj.get(column).unwrap().clone());
            }
        }

        // Ejecutar el lote
        log_debug_msg(&format!("Executing replaceIntoMany SQL: {}", replace_sql));
        log_debug_msg(&format!("Parameters count: {}", params.len()));

        match connection.execute_raw(&replace_sql, params.clone()).await {
            Ok(_) => {
                total_replaced += chunk.len();
                batches_processed += 1;
                log_debug_msg(&format!(
                    "Replace batch {} completed: {} records replaced",
                    batches_processed,
                    chunk.len()
                ));
            }
            Err(e) => {
                let error_msg = format!("Replace batch {} failed: {}", batches_processed + 1, e);
                errors.push(error_msg.clone());
                log_debug_msg(&error_msg);

                return Err((
                    format!(
                        "replaceIntoMany failed at batch {}: {}. Total replaced before failure: {}",
                        batches_processed + 1,
                        e,
                        total_replaced
                    ),
                    Some(replace_sql),
                    Some(params),
                ));
            }
        }
    }

    // Invalidar caché para esta tabla después de REPLACE INTO
    cache::invalidate_cache_for_table(table_name);
    log_debug_msg(&format!("Invalidated cache for table: {}", table_name));

    Ok(serde_json::json!({
        "total_replaced": total_replaced,
        "batches_processed": batches_processed,
        "batch_size": batch_size,
        "total_records": records.len(),
        "status": "success",
        "errors": errors
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
            "postgres" | "postgresql" | "pgsql" => {
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

/// Maneja acciones de planificación de consultas
async fn handle_query_plan_action(
    connection_manager: &mut ConnectionManager,
    params: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    log_info_msg("Processing query plan action");

    // Extraer operaciones del payload
    let operations = params
        .get("operations")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Missing or invalid operations array".to_string())?;

    // Extraer configuración de optimización
    let optimize_config = params.get("optimize").unwrap_or(&serde_json::Value::Null);

    // Convertir operaciones a formato interno
    let mut query_operations = Vec::new();
    for op in operations {
        let operation = convert_to_query_operation(op)?;
        query_operations.push(operation);
    }

    // Crear optimizador con configuración
    let optimizer = create_optimizer_from_config(optimize_config);

    // Crear plan optimizado
    let plan = optimizer.create_plan(query_operations);

    log_info_msg(&format!(
        "Query plan created with {} operations, estimated cost: {}",
        plan.operations.len(),
        plan.estimated_cost
    ));

    // Generar SQL optimizado
    let (sql, _params) = optimizer.generate_optimized_sql(&plan);

    log_debug_msg(&format!("Generated optimized SQL: {}", sql));

    // Asegurar conexión
    if connection_manager.get_pool().is_none() {
        connection_manager
            .connect()
            .await
            .map_err(|e| e.to_string())?;
    }

    let pool = connection_manager
        .get_pool()
        .ok_or("No database connection")?;

    let result = match pool {
        crate::connection::DatabasePool::MySql(pool) => {
            match sqlx::query(&sql).fetch_all(pool).await {
                Ok(rows) => {
                    let data: Vec<serde_json::Value> = rows
                        .into_iter()
                        .map(|row| {
                            let mut obj = serde_json::Map::new();
                            for column in row.columns().iter() {
                                let value = crate::utils::simple_value_placeholder();
                                obj.insert(column.name().to_string(), value);
                            }
                            serde_json::Value::Object(obj)
                        })
                        .collect();
                    serde_json::Value::Array(data)
                }
                Err(e) => {
                    log_error_msg(&format!("Query plan execution failed: {}", e));
                    return Err(format!("Query execution failed: {}", e));
                }
            }
        }
        crate::connection::DatabasePool::Postgres(pool) => {
            match sqlx::query(&sql).fetch_all(pool).await {
                Ok(rows) => {
                    let data: Vec<serde_json::Value> = rows
                        .into_iter()
                        .map(|row| {
                            let mut obj = serde_json::Map::new();
                            for column in row.columns().iter() {
                                let value = crate::utils::simple_value_placeholder();
                                obj.insert(column.name().to_string(), value);
                            }
                            serde_json::Value::Object(obj)
                        })
                        .collect();
                    serde_json::Value::Array(data)
                }
                Err(e) => {
                    log_error_msg(&format!("Query plan execution failed: {}", e));
                    return Err(format!("Query execution failed: {}", e));
                }
            }
        }
        crate::connection::DatabasePool::Sqlite(pool) => {
            match sqlx::query(&sql).fetch_all(pool).await {
                Ok(rows) => {
                    let data: Vec<serde_json::Value> = rows
                        .into_iter()
                        .map(|row| {
                            let mut obj = serde_json::Map::new();
                            for column in row.columns().iter() {
                                let value = crate::utils::simple_value_placeholder();
                                obj.insert(column.name().to_string(), value);
                            }
                            serde_json::Value::Object(obj)
                        })
                        .collect();
                    serde_json::Value::Array(data)
                }
                Err(e) => {
                    log_error_msg(&format!("Query plan execution failed: {}", e));
                    return Err(format!("Query execution failed: {}", e));
                }
            }
        }
    };

    Ok(result)
}

/// Maneja acciones de explicación de planes
async fn handle_explain_plan_action(
    params: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    log_info_msg("Processing explain plan action");

    // Extraer operaciones del payload
    let operations = params
        .get("operations")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Missing or invalid operations array".to_string())?;

    // Extraer configuración de optimización
    let optimize_config = params.get("optimize").unwrap_or(&serde_json::Value::Null);

    // Convertir operaciones a formato interno
    let mut query_operations = Vec::new();
    for op in operations {
        let operation = convert_to_query_operation(op)?;
        query_operations.push(operation);
    }

    // Crear optimizador con configuración
    let optimizer = create_optimizer_from_config(optimize_config);

    // Crear plan optimizado
    let plan = optimizer.create_plan(query_operations);

    // Generar SQL para mostrar al usuario
    let (sql, _) = optimizer.generate_optimized_sql(&plan);

    // Construir respuesta con información del plan
    let explain_info = serde_json::json!({
        "plan": {
            "operations_count": plan.operations.len(),
            "estimated_cost": plan.estimated_cost,
            "optimization_notes": plan.optimization_notes,
            "is_lazy": plan.is_lazy,
            "can_combine": plan.can_combine
        },
        "generated_sql": sql,
        "original_operations_count": operations.len(),
        "optimizations_applied": !plan.optimization_notes.is_empty()
    });

    Ok(explain_info)
}

/// Convierte una operación JSON a QueryOperation
fn convert_to_query_operation(op: &serde_json::Value) -> Result<QueryOperation, String> {
    let operation_type = op
        .get("operation_type")
        .and_then(|v| v.as_str())
        .unwrap_or("SELECT")
        .to_string();

    let table = op
        .get("table")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing table name".to_string())?
        .to_string();

    let columns = op
        .get("columns")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_else(|| vec!["*".to_string()]);

    // Convertir condiciones
    let conditions = op
        .get("conditions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    Some(QueryCondition {
                        column: c.get("column")?.as_str()?.to_string(),
                        operator: c.get("operator")?.as_str()?.to_string(),
                        value: c.get("value")?.clone(),
                        connector: c
                            .get("connector")
                            .and_then(|v| v.as_str())
                            .unwrap_or("AND")
                            .to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // Convertir JOINs
    let join_conditions = op
        .get("join_conditions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|j| {
                    Some(JoinCondition {
                        table: j.get("table")?.as_str()?.to_string(),
                        join_type: j.get("join_type")?.as_str()?.to_string(),
                        local_column: j.get("local_column")?.as_str()?.to_string(),
                        foreign_column: j.get("foreign_column")?.as_str()?.to_string(),
                        operator: j
                            .get("operator")
                            .and_then(|v| v.as_str())
                            .unwrap_or("=")
                            .to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // Convertir ORDER BY
    let ordering = op
        .get("ordering")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|o| {
                    Some(OrderBy {
                        column: o.get("column")?.as_str()?.to_string(),
                        direction: o.get("direction")?.as_str()?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // Otros campos
    let grouping = op
        .get("grouping")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let having = op
        .get("having")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|h| {
                    Some(QueryCondition {
                        column: h.get("column")?.as_str()?.to_string(),
                        operator: h.get("operator")?.as_str()?.to_string(),
                        value: h.get("value")?.clone(),
                        connector: h
                            .get("connector")
                            .and_then(|v| v.as_str())
                            .unwrap_or("AND")
                            .to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let limit = op.get("limit").and_then(|v| v.as_i64());
    let offset = op.get("offset").and_then(|v| v.as_i64());

    // Convertir relaciones (simplificado por ahora)
    let relations = op
        .get("relations")
        .and_then(|v| v.as_array())
        .map(|_arr| Vec::new()) // Simplificado por ahora
        .unwrap_or_default();

    Ok(QueryOperation {
        operation_type,
        table,
        columns,
        conditions,
        join_conditions,
        ordering,
        grouping,
        having,
        limit,
        offset,
        relations,
    })
}

/// Crea un optimizador a partir de la configuración
fn create_optimizer_from_config(config: &serde_json::Value) -> QueryOptimizer {
    let mut optimizer = QueryOptimizer::default();

    if let Some(join_opt) = config
        .get("enable_join_optimization")
        .and_then(|v| v.as_bool())
    {
        optimizer.enable_join_optimization = join_opt;
    }

    if let Some(where_opt) = config
        .get("enable_where_combination")
        .and_then(|v| v.as_bool())
    {
        optimizer.enable_where_combination = where_opt;
    }

    if let Some(subquery_opt) = config
        .get("enable_subquery_elimination")
        .and_then(|v| v.as_bool())
    {
        optimizer.enable_subquery_elimination = subquery_opt;
    }

    if let Some(max_ops) = config
        .get("max_operations_to_combine")
        .and_then(|v| v.as_u64())
    {
        optimizer.max_operations_to_combine = max_ops as usize;
    }

    optimizer
}

/// Maneja operaciones de SQL avanzadas como CTEs, Window Functions, operaciones JSON, etc.
async fn handle_advanced_sql_action(
    connection: &ConnectionManager,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (String, Option<String>, Option<Vec<serde_json::Value>>)> {
    let operation_type = params.get("operation_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ("Missing operation_type for advanced SQL".to_string(), None, None))?;

    log_debug_msg(&format!("Processing advanced SQL operation: {}", operation_type));

    match operation_type {
        "window_function" => handle_window_function(connection, params).await,
        "cte" => handle_cte_operation(connection, params).await,
        "union" => handle_union_operation(connection, params).await,
        "advanced_aggregation" => handle_advanced_aggregation(connection, params).await,
        "json_operation" => handle_json_operation(connection, params).await,
        "full_text_search" => handle_database_specific_operation(connection, params).await,
        "get_driver_capabilities" => handle_database_specific_operation(connection, params).await,
        "get_driver_limits" => handle_database_specific_operation(connection, params).await,
        "optimize_query" => handle_database_specific_operation(connection, params).await,
        "database_specific" => handle_database_specific_operation(connection, params).await,
        _ => Err((
            format!("Unknown advanced SQL operation: {}", operation_type),
            None,
            None,
        )),
    }
}

/// Maneja operaciones con Window Functions
async fn handle_window_function(
    connection: &ConnectionManager,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (String, Option<String>, Option<Vec<serde_json::Value>>)> {
    let table = params.get("table")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ("Missing table for window function".to_string(), None, None))?;

    let window_function = params.get("function")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ("Missing window function type".to_string(), None, None))?;

    let column = params.get("column")
        .and_then(|v| v.as_str())
        .unwrap_or("*");

    // Construir la función window usando el módulo advanced_sql
    let advanced_sql = AdvancedSqlFeatures::new();

    let window_clause = match window_function {
        "row_number" => {
            let partition_by = params.get("partition_by")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<String>>())
                .unwrap_or_default();

            let order_by = params.get("order_by")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| (s.to_string(), "ASC".to_string()))).collect::<Vec<(String, String)>>())
                .unwrap_or_default();

            advanced_sql.build_window_function(
                "ROW_NUMBER",
                None,
                &partition_by,
                &order_by,
                connection.get_driver()
            )
        },
        "rank" => {
            let partition_by = params.get("partition_by")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<String>>())
                .unwrap_or_default();

            let order_by = params.get("order_by")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| (s.to_string(), "ASC".to_string()))).collect::<Vec<(String, String)>>())
                .unwrap_or_default();

            advanced_sql.build_window_function(
                "RANK",
                None,
                &partition_by,
                &order_by,
                connection.get_driver()
            )
        },
        "dense_rank" => {
            let partition_by = params.get("partition_by")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                .unwrap_or_default();

            let order_by = params.get("order_by")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| (s.to_string(), "ASC".to_string()))).collect::<Vec<(String, String)>>())
                .unwrap_or_default();

            let partition_by_strings: Vec<String> = partition_by.iter().map(|s| s.to_string()).collect();

            advanced_sql.build_window_function(
                "DENSE_RANK",
                None,
                &partition_by_strings,
                &order_by,
                connection.get_driver()
            )
        },
        "lag" | "lead" => {
            let offset = params.get("offset")
                .and_then(|v| v.as_i64())
                .unwrap_or(1);

            let default_value = params.get("default_value")
                .and_then(|v| v.as_str())
                .unwrap_or("NULL");

            let partition_by = params.get("partition_by")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                .unwrap_or_default();

            let order_by = params.get("order_by")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| (s.to_string(), "ASC".to_string()))).collect::<Vec<(String, String)>>())
                .unwrap_or_default();

            let partition_by_strings: Vec<String> = partition_by.iter().map(|s| s.to_string()).collect();

            advanced_sql.build_window_function(
                window_function,
                Some(column),
                &partition_by_strings,
                &order_by,
                connection.get_driver()
            )
        },
        "sum" | "avg" | "count" | "min" | "max" => {
            let partition_by = params.get("partition_by")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                .unwrap_or_default();

            let order_by = params.get("order_by")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| (s.to_string(), "ASC".to_string()))).collect::<Vec<(String, String)>>())
                .unwrap_or_default();

            let partition_by_strings: Vec<String> = partition_by.iter().map(|s| s.to_string()).collect();

            advanced_sql.build_window_function(
                window_function,
                Some(column),
                &partition_by_strings,
                &order_by,
                connection.get_driver()
            )
        },
        _ => return Err((
            format!("Unsupported window function: {}", window_function),
            None,
            None,
        )),
    };

    // Manejar el Result de window_clause
    let window_clause_str = match window_clause {
        Ok(clause) => clause,
        Err(err) => return Err((err, None, None)),
    };

    // Construir la consulta completa
    let select_columns = params.get("select")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
        .unwrap_or_else(|| "*".to_string());

    let alias = params.get("alias")
        .and_then(|v| v.as_str())
        .unwrap_or("window_result");

    let sql = format!(
        "SELECT {}, {} AS {} FROM {}",
        select_columns, window_clause_str, alias, table
    );

    // Agregar cláusulas WHERE si existen
    let mut final_sql = sql;
    let mut bindings = Vec::new();

    if let Some(where_conditions) = params.get("where").and_then(|v| v.as_array()) {
        let where_clause = build_where_clause(where_conditions, &mut bindings)?;
        final_sql.push_str(&format!(" WHERE {}", where_clause));
    }

    // Agregar ORDER BY si existe
    if let Some(order_by) = params.get("final_order_by").and_then(|v| v.as_array()) {
        let order_clause: Vec<String> = order_by.iter()
            .filter_map(|v| {
                let obj = v.as_object()?;
                let column = obj.get("column")?.as_str()?;
                let direction = obj.get("direction")?.as_str().unwrap_or("ASC");
                Some(format!("{} {}", column, direction))
            })
            .collect();

        if !order_clause.is_empty() {
            final_sql.push_str(&format!(" ORDER BY {}", order_clause.join(", ")));
        }
    }

    // Agregar LIMIT si existe
    if let Some(limit) = params.get("limit").and_then(|v| v.as_i64()) {
        final_sql.push_str(&format!(" LIMIT {}", limit));
    }

    log_debug_msg(&format!("Executing window function SQL: {}", final_sql));

    // Ejecutar la consulta
    let rows = connection.execute_raw(&final_sql, bindings.clone())
        .await
        .map_err(|e| {
            (
                format!("Window function query failed: {}", e),
                Some(final_sql.clone()),
                Some(bindings),
            )
        })?;

    Ok(serde_json::to_value(rows).unwrap())
}

/// Maneja operaciones con CTEs (Common Table Expressions)
async fn handle_cte_operation(
    connection: &ConnectionManager,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (String, Option<String>, Option<Vec<serde_json::Value>>)> {
    let advanced_sql = AdvancedSqlFeatures::new();

    // Verificar soporte de CTEs para el motor actual
    if !advanced_sql.supports_ctes(connection.get_driver()) {
        return Err((
            format!("CTEs are not supported for database driver: {}", connection.get_driver()),
            None,
            None,
        ));
    }

    let cte_definitions = params.get("ctes")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ("Missing CTE definitions".to_string(), None, None))?;

    let main_query = params.get("main_query")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ("Missing main query for CTE".to_string(), None, None))?;

    let mut cte_clauses = Vec::new();
    let mut all_bindings = Vec::new();

    // Procesar cada CTE
    for cte in cte_definitions {
        let name = cte.get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ("Missing CTE name".to_string(), None, None))?;

        let query = cte.get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ("Missing CTE query".to_string(), None, None))?;

        // Obtener bindings para esta CTE si existen
        if let Some(bindings) = cte.get("bindings").and_then(|v| v.as_array()) {
            all_bindings.extend(bindings.clone());
        }

        // Construir la definición de CTE
        let cte_clause = format!("{} AS ({})", name, query);
        cte_clauses.push(cte_clause);
    }

    // Obtener bindings del main_query si existen
    if let Some(main_bindings) = params.get("main_query_bindings").and_then(|v| v.as_array()) {
        all_bindings.extend(main_bindings.clone());
    }

    // Construir la consulta CTE completa
    let cte_sql = advanced_sql.build_cte(&cte_clauses, main_query);

    log_debug_msg(&format!("Executing CTE SQL: {}", cte_sql));

    // Ejecutar la consulta CTE
    let rows = connection.execute_raw(&cte_sql, all_bindings.clone())
        .await
        .map_err(|e| {
            (
                format!("CTE query failed: {}", e),
                Some(cte_sql.clone()),
                Some(all_bindings),
            )
        })?;

    Ok(serde_json::to_value(rows).unwrap())
}

/// Maneja operaciones UNION
async fn handle_union_operation(
    connection: &ConnectionManager,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (String, Option<String>, Option<Vec<serde_json::Value>>)> {
    let advanced_sql = AdvancedSqlFeatures::new();

    let queries = params.get("queries")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ("Missing queries for UNION operation".to_string(), None, None))?;

    if queries.len() < 2 {
        return Err(("UNION operation requires at least 2 queries".to_string(), None, None));
    }

    let union_type = params.get("union_type")
        .and_then(|v| v.as_str())
        .unwrap_or("UNION");

    let mut query_strings = Vec::new();
    let mut all_bindings = Vec::new();

    // Procesar cada consulta
    for query_obj in queries {
        let query = query_obj.get("sql")
            .and_then(|v| v.as_str())
            .or_else(|| query_obj.get("query").and_then(|v| v.as_str()))
            .ok_or_else(|| ("Missing query in UNION operation".to_string(), None, None))?;

        query_strings.push(query.to_string());

        // Agregar bindings si existen
        if let Some(bindings) = query_obj.get("bindings").and_then(|v| v.as_array()) {
            all_bindings.extend(bindings.clone());
        }
    }

    // Construir la consulta UNION
    let union_sql = advanced_sql.build_union(&query_strings, union_type);

    // Agregar ORDER BY global si existe
    let mut final_sql = union_sql;
    if let Some(order_by) = params.get("order_by").and_then(|v| v.as_array()) {
        let order_clause: Vec<String> = order_by.iter()
            .filter_map(|v| {
                let obj = v.as_object()?;
                let column = obj.get("column")?.as_str()?;
                let direction = obj.get("direction")?.as_str().unwrap_or("ASC");
                Some(format!("{} {}", column, direction))
            })
            .collect();

        if !order_clause.is_empty() {
            final_sql.push_str(&format!(" ORDER BY {}", order_clause.join(", ")));
        }
    }

    // Agregar LIMIT global si existe
    if let Some(limit) = params.get("limit").and_then(|v| v.as_i64()) {
        final_sql.push_str(&format!(" LIMIT {}", limit));
    }

    log_debug_msg(&format!("Executing UNION SQL: {}", final_sql));

    // Ejecutar la consulta UNION
    let rows = connection.execute_raw(&final_sql, all_bindings.clone())
        .await
        .map_err(|e| {
            (
                format!("UNION query failed: {}", e),
                Some(final_sql.clone()),
                Some(all_bindings),
            )
        })?;

    Ok(serde_json::to_value(rows).unwrap())
}

/// Maneja agregaciones avanzadas
async fn handle_advanced_aggregation(
    connection: &ConnectionManager,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (String, Option<String>, Option<Vec<serde_json::Value>>)> {
    let advanced_sql = AdvancedSqlFeatures::new();

    let table = params.get("table")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ("Missing table for advanced aggregation".to_string(), None, None))?;

    let aggregation_type = params.get("aggregation_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ("Missing aggregation type".to_string(), None, None))?;

    // Construir la función de agregación
    let aggregation_function = match aggregation_type {
        "group_concat" | "string_agg" => {
            let column = params.get("column")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ("Missing column for string aggregation".to_string(), None, None))?;

            let separator = params.get("separator")
                .and_then(|v| v.as_str())
                .unwrap_or(",");

            advanced_sql.build_string_aggregation(column, separator)
        },
        "percentile" => {
            let column = params.get("column")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ("Missing column for percentile".to_string(), None, None))?;

            let percentile = params.get("options")
                .and_then(|opts| opts.as_object())
                .and_then(|opts| opts.get("percentile"))
                .and_then(|v| v.as_f64())
                .ok_or_else(|| ("Missing percentile value".to_string(), None, None))?;

            advanced_sql.build_percentile_function(column, percentile)
        },
        "median" => {
            let column = params.get("column")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ("Missing column for median".to_string(), None, None))?;

            advanced_sql.build_percentile_function(column, 0.5)
        },
        "variance" | "stddev" => {
            let column = params.get("column")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ("Missing column for statistical function".to_string(), None, None))?;

            let function_name = match aggregation_type {
                "variance" => "VAR_POP",
                "stddev" => "STDDEV_POP",
                _ => unreachable!(),
            };

            format!("{}({})", function_name, column)
        },
        _ => return Err((
            format!("Unsupported aggregation type: {}", aggregation_type),
            None,
            None,
        )),
    };

    // Construir la consulta SELECT
    let mut select_columns = Vec::new();

    // Agregar columnas de agrupación si existen
    if let Some(group_by) = params.get("group_by").and_then(|v| v.as_array()) {
        for col in group_by {
            if let Some(col_str) = col.as_str() {
                select_columns.push(col_str.to_string());
            }
        }
    }

    // Agregar la función de agregación
    let alias = params.get("alias")
        .and_then(|v| v.as_str())
        .unwrap_or("aggregation_result");

    select_columns.push(format!("{} AS {}", aggregation_function, alias));

    let mut sql = format!(
        "SELECT {} FROM {}",
        select_columns.join(", "),
        table
    );

    let mut bindings = Vec::new();

    // Agregar cláusulas WHERE si existen y no están vacías
    if let Some(where_conditions) = params.get("wheres").and_then(|v| v.as_array()) {
        if !where_conditions.is_empty() {
            let where_clause = build_where_clause(where_conditions, &mut bindings)?;
            sql.push_str(&format!(" WHERE {}", where_clause));
        }
    }

    // Agregar GROUP BY si existe
    if let Some(group_by) = params.get("group_by").and_then(|v| v.as_array()) {
        let group_columns: Vec<String> = group_by.iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.to_string())
            .collect();

        if !group_columns.is_empty() {
            sql.push_str(&format!(" GROUP BY {}", group_columns.join(", ")));
        }
    }

    // Agregar HAVING si existe y no está vacío
    if let Some(having_conditions) = params.get("having").and_then(|v| v.as_array()) {
        if !having_conditions.is_empty() {
            let having_clause = build_where_clause(having_conditions, &mut bindings)?;
            sql.push_str(&format!(" HAVING {}", having_clause));
        }
    }

    // Agregar ORDER BY si existe
    if let Some(order_by) = params.get("order_by").and_then(|v| v.as_array()) {
        let order_clause: Vec<String> = order_by.iter()
            .filter_map(|v| {
                let obj = v.as_object()?;
                let column = obj.get("column")?.as_str()?;
                let direction = obj.get("direction")?.as_str().unwrap_or("ASC");
                Some(format!("{} {}", column, direction))
            })
            .collect();

        if !order_clause.is_empty() {
            sql.push_str(&format!(" ORDER BY {}", order_clause.join(", ")));
        }
    }

    // Agregar LIMIT si existe
    if let Some(limit) = params.get("limit").and_then(|v| v.as_i64()) {
        sql.push_str(&format!(" LIMIT {}", limit));
    }

    log_debug_msg(&format!("Executing advanced aggregation SQL: {}", sql));

    // Ejecutar la consulta
    let rows = connection.execute_raw(&sql, bindings.clone())
        .await
        .map_err(|e| {
            (
                format!("Advanced aggregation query failed: {}", e),
                Some(sql.clone()),
                Some(bindings),
            )
        })?;

    Ok(serde_json::to_value(rows).unwrap())
}

/// Maneja operaciones JSON
async fn handle_json_operation(
    connection: &ConnectionManager,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (String, Option<String>, Option<Vec<serde_json::Value>>)> {
    let advanced_sql = AdvancedSqlFeatures::new();

    // Verificar soporte de JSON
    if !advanced_sql.supports_json(connection.get_driver()) {
        return Err((
            format!("JSON operations are not supported for database driver: {}", connection.get_driver()),
            None,
            None,
        ));
    }

    let table = params.get("table")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ("Missing table for JSON operation".to_string(), None, None))?;

    let operation_type = params.get("json_operation")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ("Missing JSON operation type".to_string(), None, None))?;

    let column = params.get("column")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ("Missing JSON column".to_string(), None, None))?;

    // Construir la operación JSON
    let json_expression = match operation_type {
        "extract" => {
            let path = params.get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ("Missing JSON path for extraction".to_string(), None, None))?;

            advanced_sql.build_json_extract(column, path)
        },
        "array_length" => {
            let path = params.get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("$");

            advanced_sql.build_json_array_length(column, Some(path))
        },
        "object_keys" => {
            advanced_sql.build_json_keys(column)
        },
        "contains" => {
            let search_value = params.get("value")
                .or_else(|| params.get("search_value"))
                .ok_or_else(|| ("Missing search value for JSON contains".to_string(), None, None))?;

            let search_json = serde_json::to_string(search_value)
                .map_err(|e| (format!("Failed to serialize search value: {}", e), None, None))?;

            advanced_sql.build_json_contains(column, &search_json)
        },
        "search" => {
            let path = params.get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ("Missing JSON path for search".to_string(), None, None))?;

            let value = params.get("value")
                .ok_or_else(|| ("Missing value for JSON search".to_string(), None, None))?;

            let value_str = if value.is_string() {
                format!("'{}'", value.as_str().unwrap())
            } else {
                value.to_string()
            };

            format!("JSON_EXTRACT({}, '{}') = {}", column, path, value_str)
        },
        _ => return Err((
            format!("Unsupported JSON operation: {}", operation_type),
            None,
            None,
        )),
    };

    // Construir la consulta
    let select_columns = params.get("select")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_else(|| "*".to_string());

    let alias = params.get("alias")
        .and_then(|v| v.as_str())
        .unwrap_or("json_result");

    let mut sql = format!(
        "SELECT {}, {} AS {} FROM {}",
        select_columns, json_expression, alias, table
    );

    let mut bindings = Vec::new();

    // Agregar cláusulas WHERE si existen
    if let Some(where_conditions) = params.get("where").and_then(|v| v.as_array()) {
        let where_clause = build_where_clause(where_conditions, &mut bindings)?;
        sql.push_str(&format!(" WHERE {}", where_clause));
    }

    // Para operaciones de búsqueda, usar la expresión JSON como filtro
    if operation_type == "search" || operation_type == "contains" {
        let filter_clause = if operation_type == "contains" {
            json_expression
        } else {
            json_expression
        };

        if bindings.is_empty() {
            sql.push_str(&format!(" WHERE {}", filter_clause));
        } else {
            sql.push_str(&format!(" AND {}", filter_clause));
        }
    }

    // Agregar ORDER BY si existe
    if let Some(order_by) = params.get("order_by").and_then(|v| v.as_array()) {
        let order_clause: Vec<String> = order_by.iter()
            .filter_map(|v| {
                let obj = v.as_object()?;
                let column = obj.get("column")?.as_str()?;
                let direction = obj.get("direction")?.as_str().unwrap_or("ASC");
                Some(format!("{} {}", column, direction))
            })
            .collect();

        if !order_clause.is_empty() {
            sql.push_str(&format!(" ORDER BY {}", order_clause.join(", ")));
        }
    }

    // Agregar LIMIT si existe
    if let Some(limit) = params.get("limit").and_then(|v| v.as_i64()) {
        sql.push_str(&format!(" LIMIT {}", limit));
    }

    log_debug_msg(&format!("Executing JSON operation SQL: {}", sql));

    // Ejecutar la consulta
    let rows = connection.execute_raw(&sql, bindings.clone())
        .await
        .map_err(|e| {
            (
                format!("JSON operation query failed: {}", e),
                Some(sql.clone()),
                Some(bindings),
            )
        })?;

    Ok(serde_json::to_value(rows).unwrap())
}

/// Maneja operaciones específicas por motor de base de datos
async fn handle_database_specific_operation(
    connection: &ConnectionManager,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (String, Option<String>, Option<Vec<serde_json::Value>>)> {
    let db_features = DatabaseSpecificFeatures::new();

    let operation = params.get("operation_type")
        .and_then(|v| v.as_str())
        .or_else(|| params.get("operation").and_then(|v| v.as_str()))
        .ok_or_else(|| ("Missing database specific operation".to_string(), None, None))?;

    match operation {
        "validate_driver" => {
            let is_valid = db_features.validate_driver(connection.get_driver());
            Ok(serde_json::json!({
                "driver": connection.get_driver(),
                "is_valid": is_valid,
                "features": {
                    "supports_json": db_features.supports_json(connection.get_driver()),
                    "supports_ctes": db_features.supports_ctes(connection.get_driver()),
                    "supports_window_functions": db_features.supports_window_functions(connection.get_driver()),
                    "supports_full_text_search": db_features.supports_full_text_search(connection.get_driver()),
                }
            }))
        },
        "optimize_query" => {
            let query = params.get("query")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ("Missing query for optimization".to_string(), None, None))?;

            let optimized = db_features.optimize_query_for_driver(query, connection.get_driver());
            Ok(serde_json::json!({
                "original_query": query,
                "optimized_query": optimized,
                "driver": connection.get_driver()
            }))
        },
        "get_driver_limits" => {
            let limits = db_features.get_driver_limits(connection.get_driver());
            Ok(serde_json::to_value(limits).unwrap())
        },
        "get_driver_capabilities" => {
            Ok(serde_json::json!({
                "driver": connection.get_driver(),
                "features": {
                    "supports_json": db_features.supports_json(connection.get_driver()),
                    "supports_ctes": db_features.supports_ctes(connection.get_driver()),
                    "supports_window_functions": db_features.supports_window_functions(connection.get_driver()),
                    "supports_full_text_search": db_features.supports_full_text_search(connection.get_driver()),
                }
            }))
        },
        "full_text_search" => {
            if !db_features.supports_full_text_search(connection.get_driver()) {
                return Err((
                    format!("Full text search not supported for driver: {}", connection.get_driver()),
                    None,
                    None,
                ));
            }

            let table = params.get("table")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ("Missing table for full text search".to_string(), None, None))?;

            let columns = params.get("columns")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                })
                .ok_or_else(|| ("Missing columns for full text search".to_string(), None, None))?;

            let search_term = params.get("search_term")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ("Missing search term".to_string(), None, None))?;

            let columns_strings: Vec<String> = columns.iter().map(|s| s.to_string()).collect();
            let fts_sql = db_features.build_full_text_search(table, &columns_strings, search_term, connection.get_driver());

            log_debug_msg(&format!("Executing full text search SQL: {}", fts_sql));

            // Ejecutar la búsqueda de texto completo
            let rows = connection.execute_raw(&fts_sql, vec![])
                .await
                .map_err(|e| {
                    (
                        format!("Full text search failed: {}", e),
                        Some(fts_sql.clone()),
                        None,
                    )
                })?;

            Ok(serde_json::to_value(rows).unwrap())
        },
        _ => Err((
            format!("Unknown database specific operation: {}", operation),
            None,
            None,
        )),
    }
}

/// Helper function para construir cláusulas WHERE
fn build_where_clause(
    conditions: &[serde_json::Value],
    bindings: &mut Vec<serde_json::Value>,
) -> Result<String, (String, Option<String>, Option<Vec<serde_json::Value>>)> {
    let mut where_parts = Vec::new();

    for condition in conditions {
        let column = condition.get("column")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ("Missing column in WHERE condition".to_string(), None, None))?;

        let operator = condition.get("operator")
            .and_then(|v| v.as_str())
            .unwrap_or("=");

        let value = condition.get("value")
            .ok_or_else(|| ("Missing value in WHERE condition".to_string(), None, None))?;

        let connector = condition.get("connector")
            .and_then(|v| v.as_str())
            .unwrap_or("AND");

        // Validar el nombre de la columna
        if utils::clean_column_name(column).is_err() {
            return Err(("Invalid column name in WHERE condition".to_string(), None, None));
        }

        let condition_str = match operator.to_uppercase().as_str() {
            "IN" | "NOT IN" => {
                if let Some(values) = value.as_array() {
                    let placeholders = values.iter()
                        .map(|_| "?")
                        .collect::<Vec<_>>()
                        .join(", ");

                    for v in values {
                        bindings.push(v.clone());
                    }

                    format!("{} {} ({})", column, operator, placeholders)
                } else {
                    bindings.push(value.clone());
                    format!("{} {} (?)", column, operator)
                }
            },
            "BETWEEN" => {
                if let Some(values) = value.as_array() {
                    if values.len() == 2 {
                        bindings.push(values[0].clone());
                        bindings.push(values[1].clone());
                        format!("{} BETWEEN ? AND ?", column)
                    } else {
                        return Err(("BETWEEN operator requires exactly 2 values".to_string(), None, None));
                    }
                } else {
                    return Err(("BETWEEN operator requires an array of 2 values".to_string(), None, None));
                }
            },
            "IS NULL" | "IS NOT NULL" => {
                format!("{} {}", column, operator)
            },
            "LIKE" | "NOT LIKE" | "ILIKE" => {
                bindings.push(value.clone());
                format!("{} {} ?", column, operator)
            },
            _ => {
                bindings.push(value.clone());
                format!("{} {} ?", column, operator)
            }
        };

        if where_parts.is_empty() {
            where_parts.push(condition_str);
        } else {
            where_parts.push(format!("{} {}", connector, condition_str));
        }
    }

    Ok(where_parts.join(" "))
}
