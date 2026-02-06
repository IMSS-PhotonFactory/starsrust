/**
 * STARS server in Rust
 * Based on Perl STARS server from Takashi Kosuge; KEK Tsukuba
 * stars.kek.jp
 */
use std::{
    collections::HashSet,
    io::prelude::*,
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    process,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use clap::Parser;
use configparser::ini::Ini;
use regex::Regex;

mod definitions;
use definitions::*;
mod utilities;
use utilities::*;
mod starsdata;
use starsdata::StarsData;
mod starserror;
use starserror::StarsError;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Arguments {
    /// Portnumber of the server.
    #[arg(short, long, default_value_t = 6057)]
    port: u16,
    /// Directory with the server .cfg and .key files.
    #[arg(short, long, default_value_t = DEFAULT_LIBDIR.to_string())]
    libdir: String,
    /// Directory with the server .key files. If empty lib directory will be used.
    #[arg(short, long, default_value_t = String::from(""))]
    keydir: String,
    /// Read timeout in msec
    #[arg(short, long, default_value_t = READ_TIMEOUT)]
    timeout: u64,
}

struct Param {
    port: u16,
    libdir: String,
    keydir: String,
    timeout: u64,
}

fn read_parameter(args: Arguments) -> Param {
    Param {
        port: args.port,
        libdir: args.libdir,
        keydir: args.keydir,
        timeout: args.timeout,
    }
}

fn read_config_file(fname: &str) -> GenericResult<Param> {
    let mut config = Ini::new();
    config.load(fname)?;
    let p = config
        .get("param", "starsport")
        .ok_or(GenericError::from(StarsError {
            message: "starsport keyword not found!".to_string(),
        }))?;
    let lb = config
        .get("param", "starslib")
        .ok_or(GenericError::from(StarsError {
            message: "starslib keyword not found!".to_string(),
        }))?;
    let kd = config
        .get("param", "starskey")
        .ok_or(GenericError::from(StarsError {
            message: "starskey keyword not found!".to_string(),
        }))?;
    let to = config
        .get("param", "timeout")
        .ok_or(GenericError::from(StarsError {
            message: "timeout keyword not found!".to_string(),
        }))?;
    let param = Param {
        port: p.parse()?,
        libdir: lb,
        keydir: kd,
        timeout: to.parse()?,
    };
    println!("Config file found.");
    Ok(param)
}

// Use lazy_static (see definitions.rs) to avoid to construct the regex pattern over and over
lazy_static! {
    static ref SEARCHFROM: Regex = Regex::new(r"([a-zA-Z_0-9.\-]+)>").expect("Error parsing regex");
    static ref SEARCHTO: Regex =
        Regex::new(r"^([a-zA-Z_0-9.\-]+)\s*").expect("Error parsing regex");
    static ref SEARCHCMD1: Regex = Regex::new(r"^[^@]").expect("Error parsing regex");
    static ref SEARCHCMD2: Regex = Regex::new(r"^[^_]").expect("Error parsing regex");
    static ref SEARCHCMD3: Regex = Regex::new(r"^[_@]").expect("Error parsing regex");
    static ref SEARCHDISCONN: Regex = Regex::new(r"disconnect ").expect("Error parsing regex");
    static ref SEARCHFLGON: Regex = Regex::new(r"flgon ").expect("Error parsing regex");
    static ref SEARCHFLGOFF: Regex = Regex::new(r"flgoff ").expect("Error parsing regex");
    static ref SEARCHSPLIT: Regex = Regex::new(r"\r*\n").expect("Error parsing regex");
    static ref SEARCHEXIT: Regex = Regex::new(r"(?i)^(exit|quit)").expect("Error parsing regex");
    static ref SEARCHPARAM: Regex =
        Regex::new(r"^([a-zA-Z_0-9.\-]+)").expect("Error parsing regex");
}

fn main() {
    let args = Arguments::parse();

    println!();
    println!("STARS Server Version: {VERSION}");
    dbprint!("ON");
    println!();

    let mut param = match read_config_file(CONFIG_FILE) {
        Ok(p) => p,
        Err(err) => {
            let msg = format!("{err}");
            println!(
                "No config file found or error at reading file!\n{msg}\nUsing given or default arguments."
            );
            read_parameter(args)
        }
    };
    if param.keydir.is_empty() {
        param.keydir = param.libdir.clone();
    }

    println!("--- Parameters ---");
    println!(" Port: {}", param.port);
    println!(" Lib: {}", param.libdir);
    println!(" Key: {}", param.keydir);
    println!(" Timeout: {}", param.timeout);
    println!("------------------");
    println!();

    let port = param.port;
    let libdir = param.libdir;
    let tout: Option<Duration> = if param.timeout > 0_u64 {
        Some(Duration::from_millis(param.timeout))
    } else {
        None
    };

    //Hashmap NodeList (Key: Nodename as String; Value: TcpStream)
    let nodes: Arc<Mutex<NodeList>> = Arc::new(Mutex::new(NodeList::new()));
    let sd: Arc<Mutex<StarsData>> = Arc::new(Mutex::new(StarsData::new(&libdir, &param.keydir)));

    // Code-Block: make sure the lock() will be dropped! (maybe not necessary)
    {
        let mut sdata = sd.lock().expect("can't get the lock!");
        startcheck(system_load_commandpermission(&mut sdata));
        startcheck(system_load_aliases(&mut sdata));
        startcheck(system_load_reconnecttable_permission(&mut sdata));
        system_load_shutdown_permission(&mut sdata);
    }
    // drop the lock here

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = match TcpListener::bind(addr) {
        Ok(listener) => listener,
        Err(err) => {
            panic!("{} {}", "ERROR: Can't create socket for listining! ", err);
        }
    };

    println!("Server started. Time: {}", system_get_time());
    println!();
    // Server init done!

    // listener loop: handles all incomming connections to the server.
    loop {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let (host, ip) = system_get_hostname_or_ip(&stream);
                dbprint!((&host, &ip));
                if !system_check_host(HOST_LIST, &host, &ip, false, &libdir) {
                    let errmsg = format!("Bad host. {host}\n");
                    {
                        let mut nodes_list = nodes.lock().expect("can't get the lock!");
                        writemsg(
                            &stream.try_clone().expect("stream clone failed!"),
                            errmsg,
                            &mut nodes_list,
                        );
                    }
                    stream
                        .shutdown(Shutdown::Both)
                        .expect("shutdown call failed")
                } else {
                    let nodekey = get_node_id_key();
                    let msg = format!("{nodekey}\n");
                    {
                        let mut nodes_list = nodes.lock().expect("can't get the lock!");
                        writemsg(
                            &stream.try_clone().expect("stream clone failed!"),
                            msg,
                            &mut nodes_list,
                        );
                    }
                    let rmsg = match recvmsg(
                        stream.try_clone().expect("stream clone failed!"),
                        "unknown",
                        tout,
                    ) {
                        Ok(rmsg) => rmsg,
                        Err(err) => {
                            eprintln!("{err}");
                            String::new()
                        }
                    };
                    dbprint!(rmsg);
                    if !rmsg.is_empty() {
                        match addnode(
                            stream.try_clone().expect("stream clone failed!"),
                            rmsg.trim().to_string(),
                            nodekey,
                            &nodes,
                            &mut sd.lock().expect("can't get the lock!"),
                        ) {
                            Some(node) => {
                                let nodes = Arc::clone(&nodes);
                                let sd = Arc::clone(&sd);
                                thread::spawn(move || {
                                    handle_node(
                                        node,
                                        stream.try_clone().expect("stream clone failed!"),
                                        nodes,
                                        sd,
                                    );
                                });
                                continue;
                            }
                            None => {
                                match stream.shutdown(Shutdown::Both) {
                                    Ok(_) => {}
                                    Err(_) => {
                                        eprintln!("shutdown call failed");
                                    }
                                }
                                continue;
                            }
                        }
                    }
                    match stream.shutdown(Shutdown::Both) {
                        Ok(_) => {}
                        Err(_) => {
                            eprintln!("shutdown call failed");
                        }
                    }
                    continue;
                }
            }
            Err(err) => {
                eprintln!("Couldn't get client: {err:?}");
            }
        }
    }
}

fn handle_node(
    node: String,
    stream: TcpStream,
    nodes: Arc<Mutex<NodeList>>,
    sd: Arc<Mutex<StarsData>>,
) {
    let mut savebuf = String::new();
    'main: loop {
        let mut rmsg = match recvmsg(
            stream.try_clone().expect("stream clone failed!"),
            &node,
            None,
        ) {
            Ok(data) => data,
            Err(err) => {
                eprintln!("{err}");
                break 'main;
            }
        };
        if !savebuf.is_empty() {
            rmsg = format!("{savebuf}{rmsg}");
            savebuf.clear();
        }
        if !rmsg.is_empty() {
            let mut m: Vec<_> = SEARCHSPLIT.split(&rmsg).collect();
            if let Some(pos) = m.iter().position(|x| x.is_empty()) {
                m.remove(pos);
            } else if let Some(data) = m.pop() {
                savebuf = data.to_string();
            }
            for buf in m {
                if SEARCHEXIT.is_match(buf) {
                    break 'main;
                } else {
                    sendmes(
                        &node,
                        &stream,
                        buf,
                        &mut nodes.lock().expect("can't get the lock!"),
                        &sd,
                    );
                }
            }
        } else {
            break 'main;
        }
    }
    {
        let mut nodes_list = nodes.lock().expect("can't get the lock!");
        let mut sdata = sd.lock().expect("can't get the lock!");
        delnode(&node, &mut nodes_list, &mut sdata);
    }
}

fn writemsg(stream: &TcpStream, msg: String, nodes: &mut std::sync::MutexGuard<'_, NodeList>) {
    dbprint!(msg);
    sendtonode(stream, &msg);
    sendtodebugger(&msg, nodes);
}

fn recvmsg(mut stream: TcpStream, name: &str, timeout: Option<Duration>) -> GenericResult<String> {
    match stream.set_read_timeout(timeout) {
        Ok(_) => {}
        Err(err) => {
            return Err(GenericError::from(StarsError {
                message: format!("Set timeout faild! {err}."),
            }));
        }
    }

    let mut datamsg = Vec::new();
    let mut datapiece: [u8; TCP_BUFFER_SIZE] = [0u8; TCP_BUFFER_SIZE];
    loop {
        match stream.read(&mut datapiece) {
            Ok(0) => break, // Client disconnected!
            Ok(datacount) => {
                datamsg.extend_from_slice(&datapiece[..datacount]);
                if datapiece[..datacount].contains(&b'\n') {
                    break;
                }
            }
            Err(err) => {
                eprintln!("Error reading from client ({name}): {err}");
                break;
            }
        }
    }
    let msg = String::from_utf8_lossy(&datamsg).to_string();

    if msg.is_empty() {
        Err(GenericError::from(StarsError {
            message: format!("({name}) Connection lost!"),
        }))
    } else {
        Ok(msg)
    }
}

fn sendtonode(stream: &TcpStream, msg: &String) {
    let mut writer = stream;
    match writer.write(msg.as_bytes()) {
        Ok(_success) => {}
        Err(err) => {
            eprintln!("Write Error: {err:?}");
            writer
                .shutdown(Shutdown::Both)
                .expect("shutdown call failed");
        }
    }
}

fn sendtodebugger(msg: &String, nodes: &mut NodeList) {
    if let Some(stream) = nodes.get("Debugger") {
        let mut writer = stream;
        match writer.write(msg.as_bytes()) {
            Ok(_success) => {}
            Err(err) => {
                eprintln!("Write Error: {err:?}");
                match writer.shutdown(Shutdown::Both) {
                    Ok(_) => {}
                    Err(err) => {
                        eprintln!("Shutdown call failed (Debugger): {err}");
                    }
                }
                nodes.remove("Debugger");
            }
        }
    }
}

#[allow(unused_assignments)]
fn sendmes(
    node: &str,
    stream: &TcpStream,
    msg: &str,
    nodes: &mut std::sync::MutexGuard<'_, NodeList>,
    sdata: &Arc<Mutex<StarsData>>,
) {
    let fromnodes = node.to_string();
    let mut fromnode = fromnodes.clone();
    let mut tonodes = String::new();
    let mut tonode = String::new();
    let mut buf = msg.to_string();
    match SEARCHFROM.captures(&buf) {
        None => {}
        Some(caps) => {
            fromnode = caps.get(1).unwrap().as_str().to_owned();
            buf = buf.replace(caps.get(0).unwrap().as_str(), "");
        }
    }
    match SEARCHTO.captures(&buf) {
        None => {
            let msg = format!("System>{fromnode}> @\n");
            writemsg(stream, msg, nodes);
            return;
        }
        Some(caps) => {
            tonodes = caps.get(1).unwrap().as_str().to_owned();
            buf = buf.replace(caps.get(0).unwrap().as_str(), "");
        }
    }
    let mut sd: std::sync::MutexGuard<'_, StarsData> = sdata.lock().expect("can't get the lock!");
    if let Some(to) = sd.aliasreal.get(&tonodes) {
        tonodes = to.to_string();
    }
    if SEARCHCMD1.is_match(&buf)
        && ((!sd.cmddeny.is_empty()
            && is_deny_checkcmd_deny(&fromnodes, &tonodes, &buf, &sd.cmddeny))
            || (!sd.cmdallow.is_empty()
                && is_deny_checkcmd_allow(&fromnodes, &tonodes, &buf, &sd.cmdallow)))
    {
        if SEARCHCMD2.is_match(&buf) {
            let msg = format!("System>{fromnode} @{buf} Er: Command denied.\n");
            writemsg(stream, msg, nodes);
        }
        return;
    }
    tonode = (tonodes.split(".").map(str::to_string).collect::<Vec<_>>())[0].clone();
    if tonode.contains("System") {
        system_commands(node, stream, &fromnode, &buf, &mut sd, nodes);
        return;
    }
    if let Some(from) = sd.aliasreal.get(&fromnode) {
        fromnode = from.to_string();
    }
    match nodes.get(&tonode) {
        Some(sock) => {
            let msg = format!("{fromnode}>{tonodes} {buf}\n");
            let s = sock.try_clone().expect("stream clone failed!");
            writemsg(&s, msg, nodes);
        }
        None => {
            if !SEARCHCMD3.is_match(&buf) {
                let msg = format!("System>{fromnode} @{buf} Er: {tonode} is down.\n");
                writemsg(stream, msg, nodes);
            }
        }
    }
}

fn addnode(
    stream: TcpStream,
    msg: String,
    nodekey: u16,
    nodes: &Arc<Mutex<NodeList>>,
    sdata: &mut std::sync::MutexGuard<'_, StarsData>,
) -> Option<String> {
    let node_id: Vec<String> = msg.split_whitespace().map(str::to_string).collect();
    if node_id.len() != 2 {
        return None;
    }
    let mut node = node_id[0].clone();
    let idmess = &node_id[1]; //.clone();

    let mut nodes_list = nodes.lock().expect("can't get the lock!");

    if let Some(s) = nodes_list.get(&node) {
        let stream_ref = s.try_clone().expect("stream clone failed!");
        if !check_reconnecttable(&node, &stream_ref, sdata) {
            let existmsg = format!("System> Er: {node} already exists.\n");
            writemsg(&stream, existmsg, &mut nodes_list);
            return None;
        } else {
            delnode(&node, &mut nodes_list, sdata);
        }
    }
    if !check_term_and_host(&node, &stream, &sdata.libdir) {
        let errmsg = format!("System> Er: Bad host for {}\n", &node);
        writemsg(&stream, errmsg, &mut nodes_list);
        return None;
    }
    if !check_nodekey(&node, nodekey as usize, idmess, &sdata.keydir) {
        let errmsg = "System> Er: Bad node name or key\n".to_string();
        writemsg(&stream, errmsg, &mut nodes_list);
        return None;
    }

    let msg_ok = format!("System>{node} Ok:\n");
    writemsg(
        &stream.try_clone().expect("stream clone failed!"),
        msg_ok,
        &mut nodes_list,
    );
    nodes_list.insert(node.clone(), stream);
    if let Some(n) = sdata.realalias.get(&node) {
        node = n.to_string();
    }
    for key_val in &sdata.nodes_flgon {
        if key_val.1.contains(&node) {
            let topre: Vec<String> = key_val.0.split(".").map(str::to_string).collect();
            if let Some(sock) = nodes_list.get(&topre[0]) {
                let s = sock.try_clone().expect("stream clone failed!");
                let msg = format!("{}>{} _Connected\n", node, key_val.0);
                writemsg(&s, msg, &mut nodes_list);
            }
        }
    }
    Some(node)
}

fn delnode(
    node: &str,
    nodes: &mut std::sync::MutexGuard<'_, NodeList>,
    sdata: &mut std::sync::MutexGuard<'_, StarsData>,
) {
    if let Some(s) = nodes.remove(node) {
        let mut node = node.to_string();
        let stream_ref = s.try_clone().expect("stream clone failed!");
        match stream_ref.shutdown(Shutdown::Both) {
            Ok(_) => (),
            Err(err) => {
                eprintln!("Shutdown call failed ({}): {}", &node, err);
            }
        }
        sdata.nodes_flgon.remove(&node);
        if let Some(n) = sdata.realalias.get(&node) {
            node = n.to_string();
        }
        for key_val in &sdata.nodes_flgon {
            if key_val.1.contains(&node) {
                let topre: Vec<String> = key_val.0.split(".").map(str::to_string).collect();
                if let Some(sock) = nodes.get(&topre[0]) {
                    let s = sock.try_clone().expect("stream clone failed!");
                    let msg = format!("{}>{} _Disconnected\n", node, key_val.0);
                    writemsg(&s, msg, nodes);
                }
            }
        }
    }
}

fn system_commands(
    node: &str,
    stream: &TcpStream,
    fromnode: &str,
    cmd: &str,
    sdata: &mut std::sync::MutexGuard<'_, StarsData>,
    nodes: &mut std::sync::MutexGuard<'_, NodeList>,
) {
    if cmd.starts_with("_") {
        system_event(node, cmd, nodes, sdata);
    } else if SEARCHDISCONN.is_match(cmd) {
        let msg = cmd.replace("disconnect ", "");
        system_disconnect(stream, fromnode, &msg, sdata, nodes);
    } else if SEARCHFLGON.is_match(cmd) {
        let msg = cmd.replace("flgon ", "");
        system_flgon(stream, fromnode, &msg, sdata, nodes);
    } else if SEARCHFLGOFF.is_match(cmd) {
        let msg = cmd.replace("flgoff ", "");
        system_flgoff(stream, fromnode, &msg, sdata, nodes);
    } else {
        match cmd {
            "loadpermission" => match system_load_commandpermission(sdata) {
                Ok(_) => {
                    let msg = format!(
                        "System>{fromnode} @loadpermission Command permission list has been loaded.\n"
                    );
                    writemsg(stream, msg, nodes);
                }
                Err(_) => {
                    let msg = format!(
                        "System>{fromnode} @loadpermission Er: Command permission list has been NOT loaded!\n"
                    );
                    writemsg(stream, msg, nodes);
                }
            },
            "loadreconnectablepermission" => match system_load_reconnecttable_permission(sdata) {
                Ok(_) => {
                    let msg = format!(
                        "System>{fromnode} @loadreconnectablepermission Reconnectable permission list has been loaded.\n"
                    );
                    writemsg(stream, msg, nodes);
                }
                Err(_) => {
                    let msg = format!(
                        "System>{fromnode} @loadreconnectablepermission Er: Reconnectable permission list has been NOT loaded!\n"
                    );
                    writemsg(stream, msg, nodes);
                }
            },
            "loadaliases" => match system_load_aliases(sdata) {
                Ok(_) => {
                    let msg = format!("System>{fromnode} @loadaliases Aliases has been loaded.\n");
                    writemsg(stream, msg, nodes);
                }
                Err(_) => {
                    let msg = format!(
                        "System>{fromnode} @loadaliases Er: Aliases has been NOT loaded!\n"
                    );
                    writemsg(stream, msg, nodes);
                }
            },
            "listaliases" => {
                let msg = format!(
                    "System>{} @listaliases {}\n",
                    fromnode,
                    system_list_aliases(sdata)
                );
                writemsg(stream, msg, nodes);
            }
            "listnodes" => {
                let msg = format!(
                    "System>{} @listnodes {}\n",
                    fromnode,
                    system_list_nodes(nodes)
                );
                writemsg(stream, msg, nodes);
            }
            "getversion" => {
                let msg =
                    format!("System>{fromnode} @getversion Version: {VERSION} (Rust Server)\n");
                writemsg(stream, msg, nodes)
            }
            "gettime" => {
                let msg = format!("System>{} @gettime {}\n", fromnode, system_get_time());
                writemsg(stream, msg, nodes)
            }
            "hello" => {
                let msg = format!("System>{fromnode} @hello Nice to meet you.\n");
                writemsg(stream, msg, nodes);
            }
            "help" => {
                let msg = format!(
                    "System>{fromnode} @help flgon flgoff loadaliases listaliases loadpermission loadreconnectablepermission listnodes shutdown getversion gettime hello disconnect\n",
                );
                writemsg(stream, msg, nodes);
            }
            "shutdown" => {
                if !sdata.shutallow.is_empty() && is_shutdowncmd_allow(fromnode, &sdata.shutallow) {
                    system_shutdown(nodes);
                } else {
                    let msg = format!("System>{fromnode} @shutdown Er: Command denied.\n");
                    writemsg(stream, msg, nodes);
                }
            }
            _ => {
                let msg = format!(
                    "System>{fromnode} @{cmd} Er: Command is not found or parameter is not enough!\n"
                );
                writemsg(stream, msg, nodes);
            }
        }
    };
}

fn system_event(
    node: &str,
    cmd: &str,
    nodes: &mut std::sync::MutexGuard<'_, NodeList>,
    sdata: &std::sync::MutexGuard<'_, StarsData>,
) {
    let mut frn = node.to_string();
    if let Some(n) = sdata.aliasreal.get(&frn) {
        frn = n.to_string();
    }
    for key_val in &sdata.nodes_flgon {
        if key_val.1.contains(&frn) {
            let topre: Vec<String> = key_val.0.split(".").map(str::to_string).collect();
            let to = &topre[0];
            if let Some(sock) = nodes.get(&topre[0]) {
                let s = sock.try_clone().expect("stream clone failed!");
                let msg = format!("{frn}>{to} {cmd}\n");
                writemsg(&s, msg, nodes);
            }
        }
    }
}

fn system_disconnect(
    stream: &TcpStream,
    fromnode: &str,
    cmd: &str,
    sdata: &mut std::sync::MutexGuard<'_, StarsData>,
    nodes: &mut std::sync::MutexGuard<'_, NodeList>,
) {
    if !SEARCHPARAM.is_match(cmd) {
        let msg = format!("System>{fromnode} @disconnect Er: Parameter is not enough.\n");
        writemsg(stream, msg, nodes);
        return;
    }
    let mut cmd = cmd.to_string();
    if let Some(v) = sdata.aliasreal.get(&cmd) {
        cmd = v.to_string();
    }
    match nodes.get(&cmd) {
        Some(_) => {}
        None => {
            let msg = format!("System>{fromnode} @disconnect Er: Node {cmd} is down.\n");
            writemsg(stream, msg, nodes);
            return;
        }
    }
    let msg = format!("System>{fromnode} @disconnect {cmd}.\n");
    writemsg(stream, msg, nodes);
    delnode(&cmd, nodes, sdata);
}

fn system_flgon(
    stream: &TcpStream,
    fromnode: &str,
    cmd: &str,
    sdata: &mut std::sync::MutexGuard<'_, StarsData>,
    nodes: &mut std::sync::MutexGuard<'_, NodeList>,
) {
    if !SEARCHPARAM.is_match(cmd) {
        let msg = format!("System>{fromnode} @disconnect Er: Parameter is not enough.\n");
        writemsg(stream, msg, nodes);
        return;
    }
    match sdata.nodes_flgon.get_mut(fromnode) {
        Some(flg_list) => {
            if flg_list.contains(cmd) {
                let msg =
                    format!("System>{fromnode} @flgon Er: Node {cmd} is allready in the list.\n");
                writemsg(stream, msg, nodes);
                return;
            }
            flg_list.insert(cmd.to_string());
            let msg = format!("System>{fromnode} @flgon Node {cmd} has been registered.\n");
            writemsg(stream, msg, nodes);
        }
        _ => {
            let mut val: HashSet<String> = HashSet::new();
            val.insert(cmd.to_string());
            sdata.nodes_flgon.insert(fromnode.to_string(), val);
            let msg = format!("System>{fromnode} @flgon Node {cmd} has been registered.\n");
            writemsg(stream, msg, nodes);
        }
    }
}

#[allow(unused_assignments)]
fn system_flgoff(
    stream: &TcpStream,
    fromnode: &str,
    cmd: &str,
    sdata: &mut std::sync::MutexGuard<'_, StarsData>,
    nodes: &mut std::sync::MutexGuard<'_, NodeList>,
) {
    if !SEARCHPARAM.is_match(cmd) {
        let msg = format!("System>{fromnode} @disconnect Er: Parameter is not enough.\n");
        writemsg(stream, msg, nodes);
        return;
    }
    match sdata.nodes_flgon.get_mut(fromnode) {
        Some(flg_list) => {
            let mut msg = String::new();
            if flg_list.remove(cmd) {
                msg = format!("System>{fromnode} @flgoff Node {cmd} has been removed.\n");
            } else {
                msg = format!("System>{fromnode} @flgoff Er: Node {cmd} is not in the list.\n");
            }
            writemsg(stream, msg, nodes);
        }
        _ => {
            let msg = format!("System>{fromnode} @flgoff Er: List is void.\n");
            writemsg(stream, msg, nodes);
        }
    }
}

fn system_shutdown(nodes: &mut std::sync::MutexGuard<'_, NodeList>) {
    println!("SYSTEM SHUTDOWN! -> {}", system_get_time());
    for (node, s) in nodes.iter_mut() {
        let stream_ref = s.try_clone().expect("stream clone failed!");
        let msg = format!("System>{} SYSTEMSHUTDOWN\n", node);
        sendtonode(&stream_ref, &msg);
        match stream_ref.shutdown(Shutdown::Both) {
            Ok(_) => (),
            Err(err) => {
                eprintln!("Shutdown call failed ({}): {}", &node, err);
            }
        }
    }
    process::exit(0);
}

fn startcheck(sc: GenericResult<()>) {
    match sc {
        Ok(_) => {}
        Err(err) => {
            eprintln!("Initialization faild! Server will not start!\n{err}");
            process::exit(1);
        }
    }
}
