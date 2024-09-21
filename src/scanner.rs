pub mod scanner;
pub mod arp;
pub use scanner::{Color, scan_ip, test_port, colorize, is_ip_v4, write_output_to_file};
pub use arp::{list_interfaces, discover_devices};