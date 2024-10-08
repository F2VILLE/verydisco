use std::env;

mod scanner;
use scanner::{Color, scan_ip, colorize, is_ip_v4, write_output_to_file};


fn print_usage(program_name: &str, options: Vec<VDOption>) {

    let mut usage = format!(
        "Usage: \n{} [options] target_ip\n\nOptions:\n",
        program_name
    );
    for option in options {
        if !option.hide {
            usage.push_str(&format!(
                "    {:<20} {} - {}\n",
                option.aliases.join(", "),
                option.name,
                option.help
            ));
        }
    }
    println!("{}", usage);
}

fn motd() {
    print!("\x1B[2J\x1B[1;1H");
    println!(
        "                                                  
\x1b[38;2;146;140;150m            \x1b[48;2;100;106;115m         \x1b[48;2;0;0;0m       \x1b[48;2;240;208;67m  \x1b[0m                        
\x1b[38;2;146;140;150m          \x1b[48;2;100;106;115m           \x1b[48;2;0;0;0m         \x1b[48;2;240;208;67m  \x1b[0m                      
\x1b[38;2;146;140;150m         \x1b[48;2;100;106;115m            \x1b[48;2;0;0;0m          \x1b[48;2;240;208;67m  \x1b[0m                     
\x1b[38;2;146;140;150m        \x1b[48;2;100;106;115m             \x1b[48;2;0;0;0m            \x1b[48;2;240;208;67m \x1b[0m                    
\x1b[38;2;146;140;150m       \x1b[48;2;100;106;115m              \x1b[48;2;0;0;0m            \x1b[48;2;240;208;67m  \x1b[0m                   
\x1b[38;2;146;140;150m     \x1b[48;2;100;106;115m                \x1b[48;2;0;0;0m            \x1b[48;2;240;208;67m   \x1b[0m                  
\x1b[38;2;146;140;150m    \x1b[48;2;100;106;115m       \x1b[48;2;0;0;0m                      \x1b[48;2;240;208;67m   \x1b[0m                  
\x1b[38;2;146;140;150m    \x1b[48;2;100;106;115m    \x1b[48;2;0;0;0m                         \x1b[48;2;240;208;67m   \x1b[0m                  
\x1b[38;2;146;140;150m    \x1b[48;2;100;106;115m    \x1b[48;2;0;0;0m                         \x1b[48;2;240;208;67m   \x1b[0m                  
\x1b[38;2;146;140;150m     \x1b[48;2;100;106;115m   \x1b[48;2;0;0;0m                         \x1b[48;2;240;208;67m  \x1b[0m                   
\x1b[38;2;146;140;150m        \x1b[48;2;100;106;115m    \x1b[48;2;0;0;0m                     \x1b[48;2;240;208;67m  \x1b[0m                   
\x1b[38;2;146;140;150m         \x1b[48;2;100;106;115m            \x1b[48;2;0;0;0m           \x1b[48;2;240;208;67m  \x1b[0m                    
\x1b[38;2;146;140;150m          \x1b[48;2;100;106;115m           \x1b[48;2;0;0;0m        \x1b[48;2;240;208;67m    \x1b[0m                     
\x1b[38;2;146;140;150m            \x1b[48;2;100;106;115m         \x1b[48;2;0;0;0m\x1b[48;2;240;208;67m           \x1b[0m                      
\x1b[38;2;146;140;150m              \x1b[48;2;100;106;115m       \x1b[48;2;0;0;0m\x1b[48;2;240;208;67m         \x1b[0m                        
\x1b[38;2;146;140;150m                \x1b[48;2;100;106;115m     \x1b[48;2;0;0;0m\x1b[48;2;240;208;67m       \x1b[0m                          
    
                                                     
 - Welcome to VeriDisco v{} -
 
",
        env!("CARGO_PKG_VERSION")
    );
}


struct VDOption {
    name: String,
    enabled: bool,
    value: String,
    aliases: Vec<String>,
    has_arg: bool,
    hide: bool,
    help: String,
}


fn main() {
    let mut options: Vec<VDOption> = Vec::new();
    options.push(VDOption {
        name: "output".to_string(),
        enabled: false,
        value: "".to_string(),
        has_arg: true,
        aliases: vec!["-o".to_string(), "--output".to_string()],
        hide: false,
        help: "Output file path".to_string(),
    });
    options.push(VDOption {
        name: "output-type".to_string(),
        enabled: false,
        value: "".to_string(),
        has_arg: true,
        aliases: vec!["-ot".to_string(), "--output-type".to_string()],
        hide: false,
        help: "Output type (json, xml, txt)".to_string(),
    });
    options.push(VDOption {
        name: "target_ip".to_string(),
        enabled: false,
        value: "".to_string(),
        has_arg: false,
        aliases: vec![],
        hide: true,
        help: "".to_string(),
    });
    options.push(VDOption {
        name: "verbose".to_string(),
        enabled: false,
        value: "".to_string(),
        has_arg: false,
        aliases: vec!["-V".to_string(), "--verbose".to_string()],
        hide: false,
        help: "Enable verbose for more details".to_string(),
    });
    options.push(VDOption {
        name: "threads".to_string(),
        enabled: false,
        value: "8".to_string(),
        has_arg: true,
        aliases: vec!["-t".to_string(), "--threads".to_string()],
        hide: false,
        help: "Number of threads for the scan".to_string(),
    });

    let args = env::args().collect::<Vec<String>>();

    let program_name = args[0].clone();

    if args.len() < 2 || args[1] == "-h" || args[1] == "--help" {
        print_usage(&program_name, options);
        return;
    }

    if args[1] == "-v" || args[1] == "--version" {
        println!("VeriDisco v{}", env!("CARGO_PKG_VERSION"));
        return;
    }

    motd();
    let mut skip = false;
    for i in 1..args.len() {
        if skip {
            skip = false;
            continue;
        }
        let arg = &args[i];
        let mut found = false;
        for option in &mut options {
            if option.aliases.contains(arg) {
                option.enabled = true;
                if i + 1 < args.len() && !args[i + 1].starts_with("-") && option.has_arg {
                    option.value = args[i + 1].clone();
                    skip = true;
                }
                found = true;
                break;
            } else if !arg.starts_with("-") && option.name == "target_ip" && is_ip_v4(arg) {
                option.value = arg.clone();
                option.enabled = true;
                found = true;
                break;
            }
        }
        if !found {
            println!("{}: {}", colorize("[X] Invalid option", Color::Red), arg);
            for option in &mut options {
                if option.enabled {
                    option.value = arg.clone();
                    option.enabled = false;
                    break;
                }
            }
        }
    }

    // get option by name
    let get_option = |name: &str| -> &VDOption {
        for option in &options {
            if option.name == name {
                return option;
            }
        }
        panic!("Option not found");
    };

    if !get_option("target_ip").enabled {
        println!("{}", colorize("[X] Target IP is required\n", Color::Red));
        print_usage(program_name.as_str(), options);
        return;
    }

    if get_option("verbose").enabled {
        for option in &options {
            if option.hide {
                continue;
            }
            println!(
                "{} {}: {}",
                if option.enabled {
                    colorize("[V]", Color::Green)
                } else {
                    colorize("[X]", Color::Red)
                },
                option.name,
                colorize(&option.value, Color::Cyan)
            );
        }
    }

    println!(
        "{}: {}\n",
        "Target IP",
        colorize(&get_option("target_ip").value, Color::Cyan)
    );

    let thread_count = get_option("threads").value.parse::<usize>().unwrap();

    let open_ports = scan_ip(&get_option("target_ip").value, thread_count);

    if get_option("output").enabled {
        write_output_to_file(
            &get_option("output").value,
            &get_option("output-type").value,
            open_ports,
        );
        println!(
            "{}: {}\n",
            "Output file",
            colorize(&get_option("output").value, Color::Cyan)
        );
    }

}
