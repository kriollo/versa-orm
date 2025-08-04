use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// Estructura para entradas de caché con TTL
#[derive(Clone, Debug)]
struct CacheEntry {
    value: String,
    expiration: Instant,
    access_count: u64,
    last_accessed: Instant,
}

impl CacheEntry {
    fn new(value: String, ttl: Duration) -> Self {
        Self {
            value,
            expiration: Instant::now() + ttl,
            access_count: 0,
            last_accessed: Instant::now(),
        }
    }

    fn is_expired(&self) -> bool {
        self.expiration < Instant::now()
    }

    fn access(&mut self) -> String {
        self.access_count += 1;
        self.last_accessed = Instant::now();
        self.value.clone()
    }
}

// Configuración de caché
struct CacheConfig {
    enabled: bool,
    max_size: usize,
    default_ttl: Duration,
    #[allow(dead_code)]
    cleanup_interval: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_size: 1000,
            default_ttl: Duration::from_secs(300), // 5 minutos por defecto
            cleanup_interval: Duration::from_secs(60), // Limpiar cada minuto
        }
    }
}

static QUERY_CACHE: Lazy<Arc<Mutex<HashMap<String, CacheEntry>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));
static SCHEMA_CACHE: Lazy<Arc<Mutex<HashMap<String, CacheEntry>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));
static CACHE_CONFIG: Lazy<Arc<Mutex<CacheConfig>>> =
    Lazy::new(|| Arc::new(Mutex::new(CacheConfig::default())));

// Funciones públicas para gestión de caché
#[allow(dead_code)]
pub fn enable_cache() {
    CACHE_CONFIG.lock().unwrap().enabled = true;
}

#[allow(dead_code)]
pub fn disable_cache() {
    CACHE_CONFIG.lock().unwrap().enabled = false;
}

#[allow(dead_code)]
pub fn is_cache_enabled() -> bool {
    CACHE_CONFIG.lock().unwrap().enabled
}

#[allow(dead_code)]
pub fn set_cache_config(max_size: usize, default_ttl_secs: u64) {
    let mut config = CACHE_CONFIG.lock().unwrap();
    config.max_size = max_size;
    config.default_ttl = Duration::from_secs(default_ttl_secs);
}

#[allow(dead_code)]
pub fn clear_cache() {
    QUERY_CACHE.lock().unwrap().clear();
    SCHEMA_CACHE.lock().unwrap().clear();
}

// Limpiar entradas expiradas
#[allow(dead_code)]
pub fn cleanup_expired_entries() {
    let mut query_cache = QUERY_CACHE.lock().unwrap();
    let mut schema_cache = SCHEMA_CACHE.lock().unwrap();
    
    query_cache.retain(|_, entry| !entry.is_expired());
    schema_cache.retain(|_, entry| !entry.is_expired());
}

// Función para hacer espacio en el caché cuando está lleno (LRU)
fn evict_lru_entries(cache: &mut HashMap<String, CacheEntry>, max_size: usize) {
    if cache.len() >= max_size {
        // Encontrar la entrada menos recientemente usada
        if let Some((oldest_key, _)) = cache
            .iter()
            .min_by_key(|(_, entry)| entry.last_accessed)
            .map(|(k, v)| (k.clone(), v.clone()))
        {
            cache.remove(&oldest_key);
        }
    }
}

// Funciones para caché de consultas con TTL
#[allow(dead_code)]
pub fn cache_query(key: &str, result: &str) {
    cache_query_with_ttl(key, result, None);
}

#[allow(dead_code)]
pub fn cache_query_with_ttl(key: &str, result: &str, ttl: Option<Duration>) {
    let config = CACHE_CONFIG.lock().unwrap();
    if !config.enabled {
        return;
    }
    
    let ttl = ttl.unwrap_or(config.default_ttl);
    let max_size = config.max_size;
    drop(config);
    
    let mut cache = QUERY_CACHE.lock().unwrap();
    
    // Evitar que el caché crezca demasiado
    evict_lru_entries(&mut cache, max_size);
    
    let entry = CacheEntry::new(result.to_string(), ttl);
    cache.insert(key.to_string(), entry);
}

#[allow(dead_code)]
pub fn get_cached_query(key: &str) -> Option<String> {
    let config = CACHE_CONFIG.lock().unwrap();
    if !config.enabled {
        return None;
    }
    drop(config);
    
    let mut cache = QUERY_CACHE.lock().unwrap();
    if let Some(entry) = cache.get_mut(key) {
        if entry.is_expired() {
            cache.remove(key);
            None
        } else {
            Some(entry.access())
        }
    } else {
        None
    }
}

// Funciones para caché de esquemas con TTL
#[allow(dead_code)]
pub fn cache_schema(key: &str, result: &str) {
    cache_schema_with_ttl(key, result, None);
}

#[allow(dead_code)]
pub fn cache_schema_with_ttl(key: &str, result: &str, ttl: Option<Duration>) {
    let config = CACHE_CONFIG.lock().unwrap();
    if !config.enabled {
        return;
    }
    
    let ttl = ttl.unwrap_or(config.default_ttl);
    let max_size = config.max_size;
    drop(config);
    
    let mut cache = SCHEMA_CACHE.lock().unwrap();
    
    // Evitar que el caché crezca demasiado
    evict_lru_entries(&mut cache, max_size);
    
    let entry = CacheEntry::new(result.to_string(), ttl);
    cache.insert(key.to_string(), entry);
}

#[allow(dead_code)]
pub fn get_cached_schema(key: &str) -> Option<String> {
    let config = CACHE_CONFIG.lock().unwrap();
    if !config.enabled {
        return None;
    }
    drop(config);
    
    let mut cache = SCHEMA_CACHE.lock().unwrap();
    if let Some(entry) = cache.get_mut(key) {
        if entry.is_expired() {
            cache.remove(key);
            None
        } else {
            Some(entry.access())
        }
    } else {
        None
    }
}

// Estadísticas del caché
#[allow(dead_code)]
pub fn cache_status() -> usize {
    let query_count = QUERY_CACHE.lock().unwrap().len();
    let schema_count = SCHEMA_CACHE.lock().unwrap().len();
    query_count + schema_count
}

#[allow(dead_code)]
pub fn cache_stats() -> serde_json::Value {
    let query_cache = QUERY_CACHE.lock().unwrap();
    let schema_cache = SCHEMA_CACHE.lock().unwrap();
    let config = CACHE_CONFIG.lock().unwrap();
    
    let query_expired = query_cache.values().filter(|entry| entry.is_expired()).count();
    let schema_expired = schema_cache.values().filter(|entry| entry.is_expired()).count();
    
    serde_json::json!({
        "enabled": config.enabled,
        "max_size": config.max_size,
        "default_ttl_secs": config.default_ttl.as_secs(),
        "query_cache": {
            "total": query_cache.len(),
            "expired": query_expired,
            "active": query_cache.len() - query_expired
        },
        "schema_cache": {
            "total": schema_cache.len(),
            "expired": schema_expired,
            "active": schema_cache.len() - schema_expired
        },
        "total_entries": query_cache.len() + schema_cache.len()
    })
}

// Invalidar caché por patrón
#[allow(dead_code)]
pub fn invalidate_cache_by_pattern(pattern: &str) {
    let mut query_cache = QUERY_CACHE.lock().unwrap();
    let mut schema_cache = SCHEMA_CACHE.lock().unwrap();
    
    query_cache.retain(|key, _| !key.contains(pattern));
    schema_cache.retain(|key, _| !key.contains(pattern));
}

// Invalidar caché después de operaciones de escritura
#[allow(dead_code)]
pub fn invalidate_cache_for_table(table_name: &str) {
    let mut query_cache = QUERY_CACHE.lock().unwrap();
    let mut schema_cache = SCHEMA_CACHE.lock().unwrap();
    
    // Invalidar consultas que involucren esta tabla
    query_cache.retain(|key, _| !key.to_lowercase().contains(&table_name.to_lowercase()));
    
    // Invalidar esquemas de esta tabla
    schema_cache.retain(|key, _| !key.to_lowercase().contains(&table_name.to_lowercase()));
}
