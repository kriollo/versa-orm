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
use std::path::PathBuf;
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

    let log_dir = PathBuf::from("logs");
    if !log_dir.exists() && fs::create_dir(&log_dir).is_err() {
        return;
    }

    let today = Local::now().format("%Y-%m-%d").to_string();
    let log_path = log_dir.join(format!("{}.log", today));

    if let Ok(file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        *LOG_FILE.lock().unwrap() = Some(file);
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
    if let Some(ref mut file) = *LOG_FILE.lock().unwrap() {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
        writeln!(file, "[{}][DEBUG] {}", timestamp, msg).unwrap();
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
                    handle_query_action(&connection_manager, &payload.params).await
                }
                "schema" => handle_schema_action(&connection_manager, &payload.params)
                    .await
                    .map_err(|e| (e, None, None)),
                "raw" => handle_raw_action(&connection_manager, &payload.params).await,
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

async fn handle_query_action(
    connection: &ConnectionManager,
    params: &serde_json::Value,
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
        query_builder.joins.push((
            join_clause.table,
            join_clause.first_col,
            join_clause.operator,
            join_clause.second_col,
            join_clause.join_type,
        ));
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
        "get" | "first" => {
            let main_results = connection
                .execute_raw(&sql, sql_params.clone())
                .await
                .map_err(|e| {
                    (
                        format!("Query execution failed: {}", e),
                        Some(sql.to_string()),
                        Some(sql_params.clone()),
                    )
                })?;

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
        _ => Err(format!("Unknown schema subject: {}", subject)),
    }
}

async fn handle_raw_action(
    connection: &ConnectionManager,
    params: &serde_json::Value,
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
        "status" => {
            let status = cache::cache_status();
            Ok(serde_json::Value::Number(serde_json::Number::from(status)))
        }
        _ => Err(format!("Unknown cache action: {}", action)),
    }
}
