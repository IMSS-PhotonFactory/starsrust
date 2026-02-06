use std::collections::{HashMap, HashSet};

// This struct holds all data from the cfg files and also the flgon list for every client.
#[derive(Debug, Clone)]
pub struct StarsData {
    pub libdir: String,
    pub keydir: String,
    pub nodes_flgon: HashMap<String, HashSet<String>>,
    pub aliasreal: HashMap<String, String>,
    pub realalias: HashMap<String, String>,
    pub cmddeny: Vec<String>,
    pub cmdallow: Vec<String>,
    pub reconndeny: Vec<String>,
    pub reconnallow: Vec<String>,
    pub shutallow: Vec<String>,
}

impl StarsData {
    pub fn new(lib: &str, key: &str) -> StarsData {
        StarsData {
            libdir: lib.to_string(),
            keydir: key.to_string(),
            nodes_flgon: HashMap::new(),
            aliasreal: HashMap::new(),
            realalias: HashMap::new(),
            cmddeny: Vec::new(),
            cmdallow: Vec::new(),
            reconndeny: Vec::new(),
            reconnallow: Vec::new(),
            shutallow: Vec::new(),
        }
    }
}
