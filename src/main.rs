use duckdb::{params, Connection};
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::{self, BufRead};
use std::path::Path;
use toxo::ParseConfig;
use toxo::{LogEntry, LogError, ParserServices};

fn main() -> () {
    let args: Vec<String> = env::args().collect();

    // Show help() if there's no arguments
    if args.len() < 2 {
        return help();
    }

    let input = args.get(1).unwrap();
    let origin = args.get(2).unwrap();
    let output = replace_extension(&input, ".db");
    let errors = replace_extension(&input, ".err");

    return parse(input, &output, &errors, origin);
}

fn parse(input: &str, output: &str, errors: &str, origin: &str) {
    println!("Preparing to read log file...");

    // Create the duckdb database and the required tables
    let conn = Connection::open(output).unwrap();
    conn.execute_batch(r"
    CREATE TYPE METHOD AS ENUM ('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE', 'PATCH');
    CREATE TYPE HTTP_VERSION AS ENUM ('HTTP/1.0', 'HTTP/1.1', 'HTTP/2.0', 'HTTP/3.0');
    CREATE TABLE IF NOT EXISTS log (
        ip                   VARCHAR NOT NULL,
        identity             VARCHAR,
        user                 VARCHAR,
        timestamp            TIMESTAMP NOT NULL,
        method               METHOD NOT NULL,
        path                 VARCHAR NOT NULL,
        extension            VARCHAR,
        query                VARCHAR,
        parsed_query         MAP(VARCHAR, VARCHAR),
        http_version         HTTP_VERSION NOT NULL,
        status_code          USMALLINT NOT NULL,
        size                 UINTEGER NOT NULL,
        referer              VARCHAR,
        referer_origin       VARCHAR,
        referer_path         VARCHAR,
        referer_query        VARCHAR,
        referer_parsed_query VARCHAR,
        user_agent           VARCHAR,
        browser              VARCHAR,
        browser_major        USMALLINT,
        browser_minor        USMALLINT,
        browser_patch        USMALLINT,
        browser_patch_minor  USMALLINT,
        os                   VARCHAR,
        os_major             USMALLINT,
        os_minor             USMALLINT,
        os_patch             USMALLINT,
        os_patch_minor       USMALLINT,
        device               VARCHAR,
        brand                VARCHAR,
        model                VARCHAR,
        country              VARCHAR,
        continent            VARCHAR,
        asn                  VARCHAR,
        as_name              VARCHAR,
        as_domain            VARCHAR,
    );
    ").unwrap();

    // Get the most recent change in the database
    let last_element: Result<Option<i64>, _> = conn.query_row(
        "SELECT timestamp FROM log ORDER BY timestamp DESC LIMIT 1",
        [],
        |row| row.get(0),
    );
    let timestamp = match last_element {
        Ok(Some(timestamp)) => timestamp,
        Ok(None) | Err(_) => 0,
    };

    // Read the log file, skipping old logs
    let config = ParseConfig::new(timestamp, origin);
    let lines = read_log_file(input);

    let mut error_file = open_or_create_file(errors);
    let mut app = conn.appender("log").unwrap();
    let mut services = ParserServices::new();
    let mut new = 0;
    let mut existing = 0;
    println!("Searching new logs...");

    // Append logs to the database
    for result in parse_line(lines, &mut services, config) {
        let log = match result {
            Ok(log) => log,
            Err(error) => {
                if !error.is_filtered() {
                    writeln!(error_file, "{}", error).unwrap();
                } else {
                    existing = existing + 1;
                    if existing % 50000 == 0 {
                        println!("Skipped logs: {}", existing);
                    }
                }
                continue;
            }
        };

        app.append_row(params![
            log.ip.to_string(),
            log.identity,
            log.user,
            log.timestamp.to_string(),
            log.method.to_string(),
            log.path,
            log.extension,
            log.query,
            log.parsed_query.map(|query| hashmap_to_string(&query)),
            log.http_version.to_string(),
            log.status_code,
            log.size,
            log.referer.map(|url| url.to_string()),
            log.referer_origin
                .map(|origin| origin.unicode_serialization()),
            log.referer_path,
            log.referer_query,
            log.referer_parsed_query
                .map(|query| hashmap_to_string(&query)),
            log.user_agent,
            log.browser,
            log.browser_major,
            log.browser_minor,
            log.browser_patch,
            log.browser_patch_minor,
            log.os,
            log.os_major,
            log.os_minor,
            log.os_patch,
            log.os_patch_minor,
            log.device,
            log.brand,
            log.model,
            log.country,
            log.continent,
            log.asn,
            log.as_name,
            log.as_domain,
        ])
        .unwrap();

        new = new + 1;
        if new % 50000 == 0 {
            println!("Adding new logs: {}", new);
        }
    }

    println!("Process finished!");
    println!("{} logs added to the database {}", new, output);
    println!("Errors are logged in the file {}", errors);
}

fn hashmap_to_string(map: &HashMap<String, String>) -> String {
    let entries: Vec<String> = map
        .iter()
        .map(|(k, v)| format!("'{}'='{}'", escape(k), escape(v)))
        .collect();
    format!("{{{}}}", entries.join(", "))
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace("'", "\\'")
}

fn parse_line<'a>(
    iterator: impl Iterator<Item = String> + 'a,
    mut services: &'a mut ParserServices,
    config: ParseConfig,
) -> Box<dyn Iterator<Item = Result<LogEntry, LogError>> + 'a> {
    Box::new(iterator.map(move |line| LogEntry::parse(line, &mut services, &config)))
}

fn read_log_file(filename: &str) -> impl Iterator<Item = String> {
    let path = Path::new(filename);
    let file = File::open(path).unwrap();
    let reader = io::BufReader::new(file);

    reader.lines().filter_map(|line| line.ok())
}

fn open_or_create_file(filename: &str) -> File {
    if Path::new(filename).exists() {
        std::fs::remove_file(filename).unwrap();
    }
    OpenOptions::new()
        .append(true)
        .create(true)
        .open(filename)
        .unwrap()
}

/** Help to show if no arguments were passed */
fn help() {
    let version = env!("CARGO_PKG_VERSION");
    println!("log2duck {}", version);
    println!("");
    println!("Run: log2duck <file> <origin>");
    println!("Example: log2duck access.log 'https://mydomain.com'");
    println!("");
}

fn replace_extension(file: &str, new_extension: &str) -> String {
    if file.ends_with(".log") {
        return format!("{}{}", &file[..file.len() - 4], new_extension);
    }
    format!("{}{}", file, new_extension)
}