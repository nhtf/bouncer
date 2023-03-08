use config::{Config, ConfigError, File};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RouteSettings {
    pub default_headers: Option<Vec<String>>,
    pub copy_headers: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub key: Option<String>,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub max_length: Option<usize>,
    pub timeout: Option<u64>,
    pub blacklist: Option<Vec<String>>,
    pub user_agent: Option<String>,
    //pub global: RouteSettings,
    pub embed: RouteSettings,
    pub proxy: RouteSettings,
}

impl Settings {
    pub fn new(name: &str) -> Result<Self, ConfigError> {
        Config::builder()
            .add_source(File::with_name(name))
            .build()?
            .try_deserialize()
    }
}
