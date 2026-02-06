use crate::{dbprint, lazy_static, starsdata::StarsData};

use super::definitions::*;

use std::{
    env,
    fs::File,
    io::{BufRead, BufReader},
    net::TcpStream,
    path::PathBuf,
    time::SystemTime,
};

use chrono::{DateTime, offset::Local};
use dns_lookup::lookup_addr;
use rand::Rng;
use regex::Regex;

pub fn get_serverdir() -> PathBuf {
    env::current_dir().expect("Error reading work directory!")
}

pub fn check_file_exists(fname: &str, libdir: &str) -> GenericResult<bool> {
    let dir: PathBuf = env::current_dir()?;
    if dir.join(libdir).join(fname).exists() {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn load_file_to_list(fname: &str, libdir: &str) -> GenericResult<Vec<String>> {
    let mut filecontent: Vec<String> = vec![];
    let filepath = get_serverdir().join(libdir).join(fname);

    let reader = BufReader::new(File::open(filepath)?);
    for line in reader.lines() {
        let lcontent = line?;
        if lcontent.starts_with('#') || lcontent.is_empty() {
        } else {
            filecontent.push(lcontent);
        }
    }
    Ok(filecontent)
}

pub fn load_file_to_map(
    fname: &str,
    sdata: &mut std::sync::MutexGuard<'_, StarsData>,
) -> GenericResult<()> {
    let filepath = get_serverdir().join(&sdata.libdir).join(fname);

    let reader = BufReader::new(File::open(filepath)?);
    for line in reader.lines() {
        let lcontent = line?;
        if lcontent.starts_with('#') || lcontent.is_empty() {
        } else {
            let aliasreal: Vec<String> = lcontent.split_whitespace().map(str::to_string).collect();
            sdata
                .aliasreal
                .insert(aliasreal[0].clone(), aliasreal[1].clone());
            sdata
                .realalias
                .insert(aliasreal[1].clone(), aliasreal[0].clone());
        }
    }
    dbprint!("load alias");
    dbprint!(sdata.aliasreal);
    dbprint!(sdata.realalias);
    Ok(())
}

pub fn load_keyfile(fname: &str, libdir: &str) -> GenericResult<Vec<String>> {
    let mut filecontent: Vec<String> = vec![];
    let filepath = get_serverdir().join(libdir).join(fname);

    let reader = BufReader::new(File::open(filepath)?);
    for line in reader.lines() {
        filecontent.push(line?.split_whitespace().map(str::to_string).collect());
    }
    Ok(filecontent)
}

pub fn get_node_id_key() -> u16 {
    let mut rng = rand::rng();
    rng.random_range(0..RNDMAX + 1)
}

pub fn system_get_time() -> String {
    let date_time: DateTime<Local> = SystemTime::now().into();
    date_time.format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn system_get_hostname_or_ip(stream: &TcpStream) -> (String, String) {
    let ip = stream.local_addr().unwrap().ip();
    match lookup_addr(&ip) {
        Ok(host) => (host, ip.to_string()),
        Err(_) => (ip.to_string(), ip.to_string()),
    }
}

pub fn system_check_host(
    fname: &str,
    hostname: &str,
    ipadr: &str,
    unchecked: bool,
    libdir: &str,
) -> bool {
    let mut check = vec![hostname];
    if hostname != ipadr {
        check.push(ipadr);
    }
    let allowed_host = match load_file_to_list(fname, libdir) {
        Ok(hosts) => hosts,
        Err(err) => {
            eprintln!("Error getting allowed host: {err}");
            return unchecked;
        }
    };

    let patterns: Vec<Regex> = allowed_host
        .iter()
        .map(|p| Regex::new(&wildcard_to_regex(p)).unwrap())
        .collect();

    for re in &patterns {
        if check.iter().any(|c| re.is_match(c)) {
            return true;
        }
    }

    unchecked
}

fn wildcard_to_regex(pattern: &str) -> String {
    let mut regex = String::from("^");
    for ch in pattern.chars() {
        match ch {
            '.' => regex.push_str(r"\."),
            '*' => regex.push_str(".*"),
            '[' | ']' | '-' => regex.push(ch), // allow range characters
            _ => regex.push_str(&regex::escape(&ch.to_string())),
        }
    }
    regex.push('$');
    regex
}

pub fn check_term_and_host(nd: &str, hd: &TcpStream, libdir: &str) -> bool {
    let file_name = nd.to_owned() + ".allow";
    if !check_file_exists(&file_name, libdir).unwrap() {
        return true;
    }
    let (host, ip) = system_get_hostname_or_ip(hd);
    if system_check_host(&file_name, &host, &ip, false, libdir) {
        return true;
    }
    false
}

pub fn check_nodekey(nname: &str, nkeynum: usize, nkeyval: &str, keydir: &str) -> bool {
    let file_name = nname.to_owned() + ".key";
    if !check_file_exists(&file_name, keydir).unwrap() {
        return false;
    }
    let kfile = load_keyfile(&file_name, keydir).unwrap();
    let mut kcount = kfile.len();
    if kcount == 0 {
        return false;
    }
    kcount = nkeynum % kcount;
    if kfile[kcount] == nkeyval {
        return true;
    }
    false
}

fn get_checkcmd_string(buf: &str) -> Option<&str> {
    lazy_static! {
        static ref RESEARCHSTR: Regex = Regex::new(r"^(\S+)( |$)").expect("Error parsing regex");
    }
    match RESEARCHSTR.captures(buf) {
        None => None,
        Some(caps) => Some(caps.get(0).unwrap().as_str()),
    }
}

pub fn is_deny_checkcmd_deny(frm: &str, to: &str, buf: &str, cmddeny: &Vec<String>) -> bool {
    let result = match get_checkcmd_string(buf) {
        None => return true,
        Some(result) => result,
    };
    let msg = format!("{frm}>{to} {result}");
    for chk in cmddeny {
        if msg.contains(chk) {
            return true;
        }
    }
    false
}

pub fn is_deny_checkcmd_allow(frm: &str, to: &str, buf: &str, cmddeny: &Vec<String>) -> bool {
    let result = match get_checkcmd_string(buf) {
        None => return true,
        Some(result) => result,
    };
    let msg = format!("{frm}>{to} {result}");
    for chk in cmddeny {
        if msg.contains(chk) {
            return false;
        }
    }
    true
}

pub fn is_deny_checkreconnecttable_deny(node: &str, host: &str, reconndeny: &Vec<String>) -> bool {
    let exp1 = &(format!(r"^{node}\s+{host}$"));
    let exp2 = &(format!(r"^{node}$"));
    let re1 = Regex::new(exp1).expect("Error parsing regex");
    let re2 = Regex::new(exp2).expect("Error parsing regex");

    for chk in reconndeny {
        if re1.is_match(chk) || re2.is_match(chk) {
            return true;
        }
    }
    false
}

pub fn is_deny_checkreconnecttable_allow(
    node: &str,
    host: &str,
    reconnallow: &Vec<String>,
) -> bool {
    let exp1 = &(format!(r"^{node}\s+{host}$"));
    let exp2 = &(format!(r"^{node}$"));
    let re1 = Regex::new(exp1).expect("Error parsing regex");
    let re2 = Regex::new(exp2).expect("Error parsing regex");

    for chk in reconnallow {
        if re1.is_match(chk) || re2.is_match(chk) {
            return false;
        }
    }
    true
}

pub fn is_shutdowncmd_allow(node: &str, shutallow: &[String]) -> bool {
    dbprint!(node);
    dbprint!(shutallow);
    if shutallow.iter().any(|n| n == node) {
        return true;
    }
    false
}

pub fn system_list_nodes(nodes: &mut std::sync::MutexGuard<'_, NodeList>) -> String {
    nodes.keys().map(|s| &**s).collect::<Vec<_>>().join(" ")
}

pub fn system_list_aliases(sdata: &mut std::sync::MutexGuard<'_, StarsData>) -> String {
    sdata
        .aliasreal
        .clone()
        .into_iter()
        .map(|(k, v)| format!("{k},{v}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn check_reconnecttable(
    node: &str,
    hd: &TcpStream,
    sdata: &mut std::sync::MutexGuard<'_, StarsData>,
) -> bool {
    if sdata.reconndeny.is_empty() && sdata.reconnallow.is_empty() {
        return false;
    }
    let host = system_get_hostname_or_ip(hd);
    if (!sdata.reconndeny.is_empty()
        && is_deny_checkreconnecttable_deny(node, &host.0, &sdata.reconndeny))
        || (!sdata.reconnallow.is_empty()
            && is_deny_checkreconnecttable_allow(node, &host.0, &sdata.reconnallow))
    {
        return false;
    }
    true
}

pub fn system_load_commandpermission(
    sdata: &mut std::sync::MutexGuard<'_, StarsData>,
) -> GenericResult<()> {
    match load_file_to_list(CMD_DENY, &sdata.libdir) {
        Ok(list) => {
            sdata.cmddeny.extend(list);
        }
        Err(err) => {
            eprintln!("Error loading {CMD_DENY} to list: {err}");
            return Err(err);
        }
    }
    match load_file_to_list(CMD_ALLOW, &sdata.libdir) {
        Ok(list) => {
            sdata.cmdallow.extend(list);
        }
        Err(err) => {
            eprintln!("Error loading {CMD_ALLOW} to list: {err}");
            return Err(err);
        }
    }
    dbprint!("load commandpermission");
    dbprint!(sdata.cmddeny);
    dbprint!((sdata.cmdallow));
    Ok(())
}

pub fn system_load_aliases(sdata: &mut std::sync::MutexGuard<'_, StarsData>) -> GenericResult<()> {
    match load_file_to_map(ALIASES, sdata) {
        Ok(_) => Ok(()),
        Err(err) => {
            eprintln!("Error loading aliases: {err}");
            Err(err)
        }
    }
}

pub fn system_load_reconnecttable_permission(
    sdata: &mut std::sync::MutexGuard<'_, StarsData>,
) -> GenericResult<()> {
    match load_file_to_list(RECONNECT_TABLE_DENY, &sdata.libdir) {
        Ok(list) => {
            sdata.reconndeny.extend(list);
        }
        Err(err) => {
            eprintln!("Error loading {RECONNECT_TABLE_DENY} to list: {err}");
            return Err(err);
        }
    }
    match load_file_to_list(RECONNECT_TABLE_ALLOW, &sdata.libdir) {
        Ok(list) => {
            sdata.reconnallow.extend(list);
        }
        Err(err) => {
            eprintln!("Error loading {RECONNECT_TABLE_ALLOW} to list: {err}");
            return Err(err);
        }
    }
    dbprint!("load reconnecttable");
    dbprint!(sdata.reconndeny);
    dbprint!(sdata.reconnallow);
    Ok(())
}

pub fn system_load_shutdown_permission(sdata: &mut std::sync::MutexGuard<'_, StarsData>) {
    match load_file_to_list(SHUTDOWN_ALLOW, &sdata.libdir) {
        Ok(list) => {
            sdata.shutallow.extend(list);
        }
        Err(_err) => {
            // Ignore error!
            // If file not exists, nobody can send the shutdown command.
        }
    }
}
