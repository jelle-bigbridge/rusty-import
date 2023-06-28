use bincode::{config, Decode, Encode};
use bytes::Bytes;
use mysql::{params, prelude::Queryable, Conn, LocalInfileHandler, Opts, Row, Value};
use regex::Regex;
use std::{
    borrow::Borrow,
    env::{self, temp_dir},
    io::{self, stdin, stdout, BufRead, Read, Write},
    path::PathBuf,
    process::{Child, Command, ExitCode, Stdio},
    str::from_utf8,
    sync::{Arc, Mutex},
};
use tempfile::TempDir;

#[derive(Debug)]
struct SshClient {
    child: Child,
}

impl SshClient {
    fn open(
        user: &str,
        host: &str,
        port: u16,
        extra_ssh_args: &[&str],
        remote_command: &str,
    ) -> Self {
        let port_str = port.to_string();
        let connect_str = format!("{}@{}", user, host);
        let mut args = vec!["-p", &port_str];
        args.extend_from_slice(extra_ssh_args);
        args.push(&connect_str);
        args.push("--");
        args.push(remote_command);
        args.push("server");
        let command = Command::new("ssh")
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to execute process");
        Self { child: command }
    }

    fn configure(&mut self, connection_url: &str) {
        self.send_command(ServerCommand::Configure(connection_url.to_string()));
    }

    fn list_tables(&mut self) -> Vec<String> {
        self.send_command(ServerCommand::ListTables);
        let reply = self.read_reply();
        match reply {
            ServerReply::ListTables(tables) => tables,
            _ => unreachable!(),
        }
    }

    fn table_structure(&mut self) -> Vec<(String, String)> {
        self.send_command(ServerCommand::TableStructure);
        let mut structures = vec![];
        loop {
            let reply = self.read_reply();
            match reply {
                ServerReply::TableStructure(table_name, structure) => {
                    structures.push((table_name, structure))
                }
                ServerReply::End => break,
                _ => unreachable!(),
            }
        }
        structures
    }

    fn download_table<'a>(&'a mut self, table_name: String, into: Box<impl io::Write>) {
        self.send_command(ServerCommand::DownloadTable(table_name.to_string()));
        let mut writer = zstd::stream::write::Decoder::new(into).unwrap();
        loop {
            let reply = self.read_reply();
            match reply {
                ServerReply::TableData(data) => {
                    writer.write_all(&data).unwrap();
                }
                ServerReply::End => break,
                _ => unreachable!(),
            }
            writer.flush().unwrap();
        }
    }

    fn read_reply(&mut self) -> ServerReply {
        let config = config::standard();
        let mut buf = [0; 4];
        self.child
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(&mut buf)
            .unwrap();
        let bytes_to_read = u32::from_be_bytes(buf);
        let mut buf = Vec::new();
        self.child
            .stdout
            .as_mut()
            .unwrap()
            .take(bytes_to_read as u64)
            .read_to_end(&mut buf)
            .unwrap();
        let (reply, read): (ServerReply, usize) = bincode::decode_from_slice(&buf, config).unwrap();
        reply
    }

    fn send_command(&mut self, command: ServerCommand) {
        assert!(matches!(self.child.try_wait(), Ok(None)));
        assert!(self.child.stdin.is_some());
        assert!(self.child.stdout.is_some());
        let config = config::standard();
        let command = bincode::encode_to_vec(&command, config).unwrap();
        self.child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&u32::to_be_bytes(command.len() as u32))
            .unwrap();
        self.child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&command)
            .unwrap();
        self.child.stdin.as_mut().unwrap().flush().unwrap();
    }

    fn kill(mut self) {
        let _ = self.child.kill();
    }
}

fn run_command(command: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(command)
        .args(args)
        .output()
        .expect("failed to execute process");
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn run_remote_command(
    server_user: &str,
    server_host: &str,
    server_port: u16,
    remote_command: &[&str],
    extra_ssh_args: &[&str],
) -> Result<String, String> {
    let port_str = server_port.to_string();
    let connect_str = format!("{}@{}", server_user, server_host);
    let mut args = vec!["-p", &port_str];
    args.extend_from_slice(extra_ssh_args);
    args.push(&connect_str);
    args.push("--");
    args.extend_from_slice(remote_command);
    println!("INFO Running remote command: {} {}", "ssh", &args.join(" "));

    run_command("ssh", &args)
}

fn copy_current_exe(
    server_user: &str,
    server_host: &str,
    server_port: u16,
    static_binary_loc: &str,
    extra_ssh_args: &[&str],
) -> Result<String, String> {
    let tmpdir = run_remote_command(
        server_user,
        server_host,
        server_port,
        &["mktemp -d \"/run/user/$(id -u)/XXXXXXXXX.rusty-import\""],
        extra_ssh_args,
    )?;
    let tmpdir = tmpdir.trim();
    let connect_str = format!("{}@{}:{}/rusty-import", server_user, server_host, tmpdir);
    let port_str = server_port.to_string();
    let mut args = vec!["-P", &port_str];
    args.extend_from_slice(extra_ssh_args);
    args.push(static_binary_loc);
    args.push(&connect_str);
    run_command("scp", &args)?;
    Ok(format!("{}/{}", tmpdir, "rusty-import"))
}

fn remove_exe(
    server_user: &str,
    server_host: &str,
    server_port: u16,
    static_binary_loc: &str,
    extra_ssh_args: &[&str],
) -> Result<String, String> {
    run_remote_command(
        server_user,
        server_host,
        server_port,
        &["rm", "-r", static_binary_loc],
        extra_ssh_args,
    )
}

#[derive(Encode, Decode, PartialEq, Debug)]
enum ServerCommand {
    Configure(String),
    ListTables,
    TableStructure,
    DownloadTable(String),
}

#[derive(Encode, Decode, PartialEq, Debug)]
enum ServerReply {
    Error(String),
    ListTables(Vec<String>),
    TableStructure(String, String),
    TableData(Vec<u8>),
    End,
}

enum State {
    Fresh,
    Configured(Config),
}

struct Config {
    conn: Conn,
}

#[derive(Debug)]
pub struct BytesLines<B> {
    buf: B,
}

impl<B> BytesLines<B> {
    pub fn new(buf: B) -> Self {
        Self { buf }
    }
}

impl<B: BufRead> Iterator for BytesLines<B> {
    type Item = io::Result<Bytes>;

    fn next(&mut self) -> Option<io::Result<Bytes>> {
        let mut buf = Vec::new();
        match self.buf.read_until(b'\n', &mut buf) {
            Ok(0) => None,
            Ok(_n) => {
                if buf.ends_with(b"\n") {
                    buf.pop();
                    if buf.ends_with(b"\r") {
                        buf.pop();
                    }
                }
                Some(Ok(Bytes::from(buf)))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

struct Context {
    config: bincode::config::Configuration,
    stdout: io::StdoutLock<'static>,
}

impl Context {
    fn new() -> Self {
        Self {
            config: bincode::config::standard(),
            stdout: io::stdout().lock(),
        }
    }

    fn print_error(&mut self, error: String) {
        let reply = ServerReply::Error(error);
        self.print_reply(reply);
    }

    fn print_reply(&mut self, reply: ServerReply) {
        let reply = bincode::encode_to_vec(reply, self.config).unwrap();
        let mut buf = [0; 4];
        buf.copy_from_slice(&(reply.len() as u32).to_be_bytes());
        self.stdout.write_all(&buf).unwrap();
        self.stdout.write_all(&reply).unwrap();
        self.stdout.flush().unwrap();
    }
}

fn run_server() -> Result<(), String> {
    let mut stdin = stdin().lock();
    let mut context = Context::new();
    let mut state = State::Fresh;

    loop {
        let mut buf = [0; 4];
        stdin.read_exact(&mut buf).map_err(|e| e.to_string())?;
        let bytes_to_read = u32::from_be_bytes(buf);
        eprintln!("Reading {} bytes", bytes_to_read);
        let mut buf = Vec::with_capacity(bytes_to_read as usize);
        stdin
            .by_ref()
            .take(bytes_to_read as u64)
            .read_to_end(&mut buf)
            .map_err(|e| e.to_string())?;
        eprintln!("Read {} bytes", buf.len());
        let (command, n): (ServerCommand, usize) =
            bincode::decode_from_slice(&buf, context.config).map_err(|e| e.to_string())?;
        eprintln!("Received command: {:?}", command);

        state = dispatch_command(&mut context, state, command);
    }
}

fn dispatch_command(context: &mut Context, state: State, command: ServerCommand) -> State {
    let res = match state {
        State::Fresh => handle_fresh(command),
        State::Configured(config) => handle_configured(context, config, command),
    };
    match res {
        Ok(state) => state,
        Err(e) => {
            context.print_error(e);
            return State::Fresh;
        }
    }
}

fn handle_fresh(command: ServerCommand) -> Result<State, String> {
    Ok(match command {
        ServerCommand::Configure(config_str) => {
            let opts = Opts::from_url(&config_str).map_err(|e| e.to_string())?;
            let conn = Conn::new(opts).map_err(|e| e.to_string())?;
            let config: Config = Config { conn };
            State::Configured(config)
        }
        ServerCommand::ListTables => return Err("Not valid when unconfigured".to_string()),
        ServerCommand::TableStructure => return Err("Not valid when unconfigured".to_string()),
        ServerCommand::DownloadTable(_) => return Err("Not valid when unconfigured".to_string()),
    })
}

fn handle_configured(
    context: &mut Context,
    mut config: Config,
    command: ServerCommand,
) -> Result<State, String> {
    Ok(match command {
        ServerCommand::Configure(config_str) => {
            let opts = Opts::from_url(&config_str).map_err(|e| e.to_string())?;
            let conn = Conn::new(opts).map_err(|e| e.to_string())?;
            let config: Config = Config { conn };
            State::Configured(config)
        }
        ServerCommand::ListTables => {
            list_tables(context, &mut config.conn);
            State::Configured(config)
        }
        ServerCommand::TableStructure => {
            table_structure(context, &mut config.conn);
            State::Configured(config)
        }
        ServerCommand::DownloadTable(table_name) => {
            download_table(context, &mut config.conn, table_name);
            State::Configured(config)
        }
    })
}

fn list_tables(ctx: &mut Context, conn: &mut Conn) {
    eprintln!("Listing tables");
    let names = list_tables_impl(conn);
    eprintln!("Tables: {:?}", names);
    ctx.print_reply(ServerReply::ListTables(names));
}

fn list_tables_impl(conn: &mut Conn) -> Vec<String> {
    let names = conn.query_iter("SHOW TABLES").unwrap().map(|row| {
        let table_name: String = mysql::from_row(row.unwrap());
        table_name
    });
    names.collect::<Vec<_>>()
}

fn table_structure(ctx: &mut Context, conn: &mut Conn) {
    for table_name in list_tables_impl(conn) {
        let stmt = conn
            .prep(format!("SHOW CREATE TABLE `{}`", table_name))
            .unwrap();
        let result = conn.exec_first(stmt, ());
        let row: Row = result.unwrap().unwrap();
        assert_eq!(row.columns().len(), 2);
        ctx.print_reply(ServerReply::TableStructure(table_name, row.get(1).unwrap()));
    }
    ctx.print_reply(ServerReply::End)
}

struct ZstdBlockPrinter<'a> {
    buf: Vec<u8>,
    context: &'a mut Context,
}
impl<'a> ZstdBlockPrinter<'a> {
    fn new(context: &'a mut Context) -> Self {
        Self {
            buf: Vec::with_capacity(1024 * 1024),
            context,
        }
    }
}

impl<'a> io::Write for ZstdBlockPrinter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (left, right) = if buf.len() < 1024 * 1024 {
            (buf, b"" as &[u8])
        } else {
            buf.split_at(1024 * 1024 - self.buf.len())
        };
        self.buf.extend_from_slice(left);
        if self.buf.len() == 1024 * 1024 {
            self.context
                .print_reply(ServerReply::TableData(self.buf.clone()));
            self.buf.clear();
        }
        self.buf.extend_from_slice(right);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.context
            .print_reply(ServerReply::TableData(self.buf.clone()));
        self.buf.clear();
        Ok(())
    }
}

/// Will escape string for SQL depending on `no_backslash_escape` flag.
fn escaped(input: &str, no_backslash_escape: bool) -> String {
    let mut output = String::with_capacity(input.len());
    // output.push('\'');
    if no_backslash_escape {
        for c in input.chars() {
            if c == '\'' {
                output.push('\'');
                output.push('\'');
            } else {
                output.push(c);
            }
        }
    } else {
        for c in input.chars() {
            if c == '\x00' {
                output.push('\\');
                output.push('0');
            } else if c == '\n' {
                output.push('\\');
                output.push('n');
            } else if c == '\r' {
                output.push('\\');
                output.push('r');
            } else if c == '\\' || c == '\'' || c == '"' {
                output.push('\\');
                output.push(c);
            } else if c == '\x1a' {
                output.push('\\');
                output.push('Z');
            } else {
                output.push(c);
            }
        }
    }
    // output.push('\'');
    output
}

fn value_as_sql(value: Value) -> String {
    match value {
        Value::NULL => "NULL".into(),
        Value::Int(x) => format!("{}", x),
        Value::UInt(x) => format!("{}", x),
        Value::Float(x) => format!("{}", x),
        Value::Double(x) => format!("{}", x),
        Value::Date(y, m, d, 0, 0, 0, 0) => format!("{:04}-{:02}-{:02}", y, m, d),
        Value::Date(year, month, day, hour, minute, second, 0) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            year, month, day, hour, minute, second
        ),
        Value::Date(year, month, day, hour, minute, second, micros) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}",
            year, month, day, hour, minute, second, micros
        ),
        Value::Time(neg, d, h, i, s, 0) => {
            if neg {
                format!("-{:03}:{:02}:{:02}", d * 24 + u32::from(h), i, s)
            } else {
                format!("{:03}:{:02}:{:02}", d * 24 + u32::from(h), i, s)
            }
        }
        Value::Time(neg, days, hours, minutes, seconds, micros) => {
            if neg {
                format!(
                    "-{:03}:{:02}:{:02}.{:06}",
                    days * 24 + u32::from(hours),
                    minutes,
                    seconds,
                    micros
                )
            } else {
                format!(
                    "{:03}:{:02}:{:02}.{:06}",
                    days * 24 + u32::from(hours),
                    minutes,
                    seconds,
                    micros
                )
            }
        }
        Value::Bytes(ref bytes) => match from_utf8(&*bytes) {
            Ok(string) => escaped(string, false),
            Err(_) => {
                let mut s = String::from("0x");
                for c in bytes.iter() {
                    s.extend(format!("{:02X}", *c).chars())
                }
                s
            }
        },
    }
}

fn download_table(ctx: &mut Context, conn: &mut Conn, table_name: String) {
    let stmt = conn
        .prep(format!("SELECT * FROM `{}`", table_name))
        .unwrap();
    let result = conn.exec_iter(stmt, ()).expect("Error executing query");
    {
        let printer = ZstdBlockPrinter::new(ctx);
        let mut encoder = zstd::stream::write::Encoder::new(printer, 0)
            .unwrap()
            .auto_finish();

        for row in result {
            let row = row.unwrap();
            for (i, value) in row.unwrap().into_iter().enumerate() {
                if i != 0 {
                    encoder.write_all(b"\t").unwrap();
                }
                encoder.write_all(value_as_sql(value).as_bytes()).unwrap();
            }
            encoder.write_all(b"\n").unwrap();
        }
        encoder.flush().unwrap();
    }
    ctx.print_reply(ServerReply::End);
}

fn main() -> Result<ExitCode, String> {
    let args = env::args().collect::<Vec<String>>();
    if args.len() > 1 && args[1] == "server" {
        eprintln!("Starting server");
        match run_server() {
            Ok(_) => return Ok(ExitCode::SUCCESS),
            Err(e) => {
                eprintln!("Error: {}", e);
                return Ok(ExitCode::FAILURE);
            }
        }
    }
    if args.len() < 6 {
        eprintln!(
            "Usage: {} <user> <host> <port> <remoteconnectionurl> <localconnectionurl>",
            args[0]
        );
        return Ok(ExitCode::FAILURE);
    }
    let ssh_tmp = TempDir::new().map_err(|e| e.to_string())?;
    let ssh_tmp_dir = ssh_tmp.path();
    let ssh_opts = [
        "-o",
        "ControlMaster=auto",
        "-o",
        &format!("ControlPath={}/ssh-%n", ssh_tmp_dir.display()),
        "-o",
        "ControlPersist=60",
    ];
    let server_user = &args[1];
    let server_host = &args[2];
    let server_port = &args[3]
        .parse::<u16>()
        .map_err(|e| format!("Invalid port: {}", e))?;
    let remote_connection_url = &args[4];
    let local_connection_url = &args[5];
    let opts = Opts::from_url(local_connection_url).map_err(|e| e.to_string())?;
    let mut conn = Conn::new(opts).map_err(|e| e.to_string())?;
    let static_binary = std::env::var("STATIC_BINARY").expect("must supply static binary location");
    let loc = copy_current_exe(
        &server_user,
        &server_host,
        *server_port,
        &static_binary,
        &ssh_opts,
    )?;
    println!("Command placed at {}", loc);
    let mut client = SshClient::open(&server_user, &server_host, *server_port, &ssh_opts, &loc);
    client.configure(remote_connection_url);
    println!("Configured");
    for table in client.list_tables() {
        println!("{}", table);
    }
    let tables = client.table_structure();
    conn.query_drop("SET FOREIGN_KEY_CHECKS=0").unwrap();
    conn.query_drop("SET unique_checks = 0").unwrap();
    // for (table_name, table_structure) in tables {
    //     println!("Creating table {}", table_name);
    //     conn.query_drop(table_structure).unwrap();
    // }
    let shared_client = Arc::new(Mutex::new(client));
    let handler_client = shared_client.clone();
    conn.set_local_infile_handler(Some(LocalInfileHandler::new(move |file_name, writer| {
        handler_client.lock().unwrap().download_table(
            "catalog_product_entity_varchar".to_string(),
            Box::new(writer),
        );
        Ok(())
    })));
    conn.query_drop("LOAD DATA LOCAL INFILE 'dummy' INTO TABLE catalog_product_entity_varchar")
        .unwrap();

    conn.query_drop("SET FOREIGN_KEY_CHECKS=1").unwrap();
    conn.query_drop("SET unique_checks = 1").unwrap();
    // Make sure there is only one strong reference to the Arc. The other one is hidden in the set_local_infile_handler closure
    drop(conn);
    let client = Arc::try_unwrap(shared_client)
        .unwrap()
        .into_inner()
        .unwrap();
    client.kill();
    let mut remove_path = PathBuf::from(&loc);
    remove_path.pop();
    println!(
        "{:?}",
        remove_exe(
            &server_user,
            &server_host,
            *server_port,
            &remove_path.to_string_lossy(),
            &ssh_opts,
        )
    );
    Ok(ExitCode::SUCCESS)
}
