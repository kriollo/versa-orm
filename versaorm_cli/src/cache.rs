use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use once_cell::sync::Lazy;

static QUERY_CACHE: Lazy<Arc<Mutex<HashMap<String, String>>>> = Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));
static SCHEMA_CACHE: Lazy<Arc<Mutex<HashMap<String, String>>>> = Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

pub fn enable_cache() {
    // Logic to enable caching might go here
}

pub fn disable_cache() {
    // Logic to disable caching might go here
}

pub fn clear_cache() {
    QUERY_CACHE.lock().unwrap().clear();
    SCHEMA_CACHE.lock().unwrap().clear();
}

pub fn cache_query(key: &str, result: &str) {
    QUERY_CACHE.lock().unwrap().insert(key.to_string(), result.to_string());
}

pub fn get_cached_query(key: &str) -> Option<String> {
    QUERY_CACHE.lock().unwrap().get(key).cloned()
}

pub fn cache_schema(key: &str, result: &str) {
    SCHEMA_CACHE.lock().unwrap().insert(key.to_string(), result.to_string());
}

pub fn get_cached_schema(key: &str) -> Option<String> {
    SCHEMA_CACHE.lock().unwrap().get(key).cloned()
}

pub fn cache_status() -> usize {
    QUERY_CACHE.lock().unwrap().len() + SCHEMA_CACHE.lock().unwrap().len()
}
