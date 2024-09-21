use serde_json;
use std::fs::File;
use std::io::Write;
use std::{
    collections::HashMap,
    net,
    sync::{Arc, Mutex},
    thread,
};


#[derive(Debug)]

pub enum Color {
    // Black = 30,
    Red = 31,
    Green = 32,
    // Yellow = 33,
    // Blue = 34,
    // Magenta = 35,
    Cyan = 36,
    // White = 37,
}

pub fn colorize(text: &str, color: Color) -> String {
    format!("\x1b[{}m{}\x1b[0m", color as i32, text)
}

pub fn is_ip_v4(ip: &str) -> bool {
    ip.split('.')
        .map(|octet| octet.parse::<u8>().is_ok())
        .fold(true, |acc, x| acc && x)
}

pub fn test_port(ip: net::IpAddr, port: u16, open_ports: Arc<Mutex<Vec<u16>>>) -> (u16, bool) {
    let socket: net::SocketAddr = net::SocketAddr::new(ip, port);
    match net::TcpStream::connect_timeout(&socket, std::time::Duration::from_millis(100)) {
        Ok(_) => {
            let mut open_ports = open_ports.lock().unwrap();
            open_ports.push(port);
            println!("Port {} is open", colorize(&port.to_string(), Color::Green));
            (port, true)
        }
        Err(_) => {
            // println!("Port {} is closed", port);
            (port, false)
        }
    }
}

pub fn scan_ip(ip: &str, thread_count: usize) -> Vec<u16> {
    println!("Seaching for open ports . . .\n");
    use std::time::Instant;
    let now = Instant::now();
    // scan ip address to discover open ports
    let ip: net::IpAddr = ip.parse().unwrap();
    let _ = match ip {
        net::IpAddr::V4(ip) => ip,
        _ => {
            println!("Only IPv4 is supported");
            return vec![];
        }
    };

    let open_ports: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(Vec::new()));

    let mut threads = vec![];
    for port_chunk in (1..65535).collect::<Vec<u16>>().chunks(thread_count) {
        for &port in port_chunk {
            let ip = ip.clone();
            let open_ports = Arc::clone(&open_ports);
            threads.push(thread::spawn(move || {
                test_port(ip, port, open_ports);
            }));
        }
        for thread in threads.drain(..) {
            // thread.join().unwrap();
            let res = thread.join();
            match res {
                Ok(_) => {}
                Err(_) => {}
            }
        }
    }

    threads.clear();
    let elapsed = now.elapsed();
    println!("Scanned 65535 ports in {} ms\n", elapsed.as_millis());
    let open_ports = open_ports.lock().unwrap();
    open_ports.clone()
}

pub fn write_output_to_file(output: &str, output_type: &str, open_ports: Vec<u16>) {
    let mut file = File::create(output).unwrap();
    match output_type {
        "json" => {
            let mut raw_json: HashMap<String, Vec<u16>> = HashMap::new();
            raw_json.insert("open_ports".to_string(), open_ports);
            let json = serde_json::to_string(&raw_json).unwrap();
            file.write_all(json.as_bytes()).unwrap();
        }
        "xml" => {
            let mut xml_output: Vec<String> = vec![];
            xml_output.push("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n".to_string());
            xml_output.push("<open_ports>\n".to_string());
            for port in open_ports {
                let port_entry = format!("<port>{}</port>\n", port);
                xml_output.push(port_entry);
            }
            xml_output.push("</open_ports>\n".to_string());
            file.write_all(xml_output.join("\n").as_bytes()).unwrap();
        }
        _ => {
            let txt = open_ports
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>()
                .join("\n");
            file.write_all(txt.as_bytes()).unwrap();
        }
    }
}
