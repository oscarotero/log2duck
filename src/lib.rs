use chrono::{DateTime, Utc};
use maxminddb::Reader;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::path::Path;
use std::{collections::HashMap, error::Error};
use ua_parser::{device, os, user_agent, Extractor, Regexes};
use url::{Origin, Url};

struct ParseError {}

impl ParseError {
    fn new() -> ParseError {
        ParseError {}
    }
}

#[derive(Debug)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    CONNECT,
    TRACE,
    PATCH,
}

impl HttpMethod {
    fn new(method: &str) -> Result<HttpMethod, ParseError> {
        match method {
            "GET" => Ok(HttpMethod::GET),
            "POST" => Ok(HttpMethod::POST),
            "PUT" => Ok(HttpMethod::PUT),
            "DELETE" => Ok(HttpMethod::DELETE),
            "HEAD" => Ok(HttpMethod::HEAD),
            "OPTIONS" => Ok(HttpMethod::OPTIONS),
            "CONNECT" => Ok(HttpMethod::CONNECT),
            "TRACE" => Ok(HttpMethod::TRACE),
            "PATCH" => Ok(HttpMethod::PATCH),
            _ => Err(ParseError::new()),
        }
    }

    pub fn to_string(&self) -> &str {
        match self {
            HttpMethod::GET => "GET",
            HttpMethod::POST => "POST",
            HttpMethod::PUT => "PUT",
            HttpMethod::DELETE => "DELETE",
            HttpMethod::HEAD => "HEAD",
            HttpMethod::OPTIONS => "OPTIONS",
            HttpMethod::CONNECT => "CONNECT",
            HttpMethod::TRACE => "TRACE",
            HttpMethod::PATCH => "PATCH",
        }
    }
}

#[derive(Debug)]
pub enum HttpVersion {
    HTTP10,
    HTTP11,
    HTTP20,
    HTTP30,
}

impl HttpVersion {
    fn new(version: &str) -> Result<HttpVersion, ParseError> {
        match version {
            "HTTP/1.0" => Ok(HttpVersion::HTTP10),
            "HTTP/1.1" => Ok(HttpVersion::HTTP11),
            "HTTP/2.0" => Ok(HttpVersion::HTTP20),
            "HTTP/3.0" => Ok(HttpVersion::HTTP30),
            _ => Err(ParseError::new()),
        }
    }

    pub fn to_string(&self) -> &str {
        match self {
            HttpVersion::HTTP10 => "HTTP/1.0",
            HttpVersion::HTTP11 => "HTTP/1.1",
            HttpVersion::HTTP20 => "HTTP/2.0",
            HttpVersion::HTTP30 => "HTTP/3.0",
        }
    }
}

pub struct ParseConfig {
    timestamp: i64,
    origin: Url,
}

impl ParseConfig {
    pub fn new(timestamp: i64, origin: &str) -> ParseConfig {
        ParseConfig {
            timestamp,
            origin: Url::parse(origin).unwrap(),
        }
    }
}

pub struct ParsedLogEntry {
    pub line: String,
    pub ip: String,
    pub identity: Option<String>,
    pub user: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub url: Url,
    pub http_version: String,
    pub status_code: u16,
    pub size: usize,
    pub referer: Option<Url>,
    pub user_agent: Option<String>,
}

impl ParsedLogEntry {
    pub fn from_json(line: String, config: &ParseConfig) -> Result<ParsedLogEntry, LogError> {
        let parsed_line: JsonLine = match serde_json::from_str(&line) {
            Ok(result) => result,
            Err(err) => {
                return Err(LogError::new(
                    &line,
                    &format!("Error parsing JSON line {}", err),
                ))
            }
        };

        // Parse ip
        let ip: String = parsed_line.request.client_ip;

        // Parse user
        let user: Option<String> = Some(parsed_line.user_id);

        // Parse timestamp
        let timestamp: DateTime<Utc> =
            match DateTime::from_timestamp(parsed_line.ts.round() as i64, 0) {
                Some(result) => result,
                None => return Err(LogError::new(&line, "Invalid timestamp")),
            };
        if timestamp.timestamp_micros() <= config.timestamp {
            return Err(LogError::new_filtered(&line));
        }

        // Method
        let method: String = parsed_line.request.method;

        // HTTP version
        let http_version: String = parsed_line.request.proto;

        // Parse URL
        let mut url = config
            .origin
            .join(&parsed_line.request.uri)
            .map_err(|_| LogError::new(&line, "Path not valid"))?;
        url.set_host(Some(&parsed_line.request.host))
            .map_err(|_| LogError::new(&line, "Host not valid"))?;

        if url.host_str() != config.origin.host_str() {
            return Err(LogError::new(&line, "Path has a different host"));
        }

        // Parse status code
        let status_code: u16 = parsed_line.status;

        // Size
        let size: usize = parsed_line.size;

        // Referer
        let referer: Option<Url> = match parsed_line.request.headers.get("Referer") {
            Some(val) => match val.first() {
                Some(str) => Url::parse(str).ok(),
                None => None,
            },
            None => None,
        };

        // Parse user agent
        let user_agent: Option<String> = match parsed_line.request.headers.get("User-Agent") {
            Some(val) => val.first().map(|s| s.to_string()),
            None => None,
        };

        Ok(ParsedLogEntry {
            line,
            ip,
            identity: None,
            user,
            timestamp,
            method,
            url,
            http_version,
            status_code,
            size,
            referer,
            user_agent,
        })
    }

    pub fn from_combined(line: String, config: &ParseConfig) -> Result<ParsedLogEntry, LogError> {
        let space = Patt::Char(' ');
        let quote = Patt::Char('"');
        let bracket = Patt::Char(']');
        let http = Patt::Str(" HTTP/");

        // Parse ip
        let (ip, next) =
            find(0, &line, &space).map_err(|_| LogError::new(&line, "IP not found"))?;

        // Parse identity
        let (identity, next) = find(next + 1, &line, &space)
            .map_err(|_| LogError::new(&line, "Identity not found"))?;
        let identity = match identity.as_str() {
            "-" => None,
            _ => Some(identity),
        };

        // Parse user
        let (user, next) =
            find(next + 1, &line, &space).map_err(|_| LogError::new(&line, "User not found"))?;
        let user = match user.as_str() {
            "-" => None,
            _ => Some(user),
        };

        // Parse timestamp
        let (timestamp, next) = find(next + 2, &line, &bracket)
            .map_err(|_| LogError::new(&line, "Datetime not found"))?;
        let timestamp = DateTime::parse_from_str(timestamp.as_str(), "%d/%b/%Y:%H:%M:%S %z")
            .map(|parsed| parsed.with_timezone(&Utc))
            .map_err(|_| LogError::new(&line, "Invalid datetime"))?;
        if timestamp.timestamp_micros() <= config.timestamp {
            return Err(LogError::new_filtered(&line));
        }

        let (request, _) =
            find(next + 3, &line, &quote).map_err(|_| LogError::new(&line, "Request not found"))?;
        if request.len() == 0 {
            return Err(LogError::new(&line, "Empty request"));
        }

        // Parse method
        let (method, next) = find(next + 3, &line, &space)
            .map_err(|_| LogError::new(&line, "HTTP method not found"))?;

        // Parse URL
        let (mut fullpath, next) =
            find(next + 1, &line, &http).map_err(|_| LogError::new(&line, "Path not found"))?;

        while fullpath.starts_with("//") {
            fullpath = fullpath.replacen("//", "/", 1);
        }

        let url = config
            .origin
            .join(&fullpath)
            .map_err(|_| LogError::new(&line, "Path not valid"))?;
        if url.host_str() != config.origin.host_str() {
            return Err(LogError::new(&line, "Path has a different host"));
        }

        // Parse HTTP version
        let (http_version, next) = find(next + 1, &line, &quote)
            .map_err(|_| LogError::new(&line, "HTTP version not found"))?;

        // Parse status code
        let (status_code, next) = find(next + 2, &line, &space)
            .map_err(|_| LogError::new(&line, "Status code not found"))?;
        let status_code: u16 = status_code
            .parse()
            .map_err(|_| LogError::new(&line, "Invalid status code"))?;

        // Parse size
        let (size, next) =
            find(next + 1, &line, &space).map_err(|_| LogError::new(&line, "Size not found"))?;
        let size: usize = size
            .parse()
            .map_err(|_| LogError::new(&line, "Invalid size"))?;

        // Parse referer
        let (referer, next) =
            find(next + 2, &line, &quote).map_err(|_| LogError::new(&line, "Referer not found"))?;
        let referer = Url::parse(&referer).ok();

        // Parse user agent
        let (user_agent, _) = find(next + 3, &line, &quote)
            .map_err(|_| LogError::new(&line, "User agent not found"))?;

        let user_agent = if user_agent.is_empty() {
            None
        } else {
            Some(user_agent)
        };

        Ok(ParsedLogEntry {
            line,
            ip,
            identity,
            user,
            timestamp,
            method,
            url,
            http_version,
            status_code,
            size,
            referer,
            user_agent,
        })
    }

    pub fn to_entry(
        self: ParsedLogEntry,
        services: &mut ParserServices,
    ) -> Result<LogEntry, LogError> {
        // Parse ip
        let ip: IpAddr = self
            .ip
            .parse()
            .map_err(|_| LogError::new(&self.line, "Invalid IP"))?;

        // Url parts
        let path = self.url.path().to_string();
        let query = self.url.query().map(|q| q.to_string());

        let extension = Path::new(&path)
            .extension()
            .map(|ext| ext.to_str().unwrap().to_lowercase().to_string());

        // Parse method
        let method = HttpMethod::new(&self.method)
            .map_err(|_| LogError::new(&self.line, "Invalid HTTP method"))?;

        // Parse HTTP version
        let http_version = HttpVersion::new(&self.http_version)
            .map_err(|_| LogError::new(&self.line, "Invalid HTTP version"))?;

        // Referer
        let (referer_origin, referer_path, referer_query) = self.referer.as_ref().map_or_else(
            || (None, None, None),
            |url| {
                (
                    Some(url.origin()),
                    Some(url.path().to_string()),
                    url.query().map(|q| q.to_string()),
                )
            },
        );

        // Parse agent data
        let (
            browser,
            browser_major,
            browser_minor,
            browser_patch,
            browser_patch_minor,
            os,
            os_major,
            os_minor,
            os_patch,
            os_patch_minor,
            device,
            brand,
            model,
        ) = self
            .user_agent
            .as_ref()
            .map(|ua| {
                let agent = services.get_agent(ua);

                (
                    agent.browser.clone(),
                    agent.browser_major.clone(),
                    agent.browser_minor.clone(),
                    agent.browser_patch.clone(),
                    agent.browser_patch_minor.clone(),
                    agent.os.clone(),
                    agent.os_major.clone(),
                    agent.os_minor.clone(),
                    agent.os_patch.clone(),
                    agent.os_patch_minor.clone(),
                    agent.device.clone(),
                    agent.brand.clone(),
                    agent.model.clone(),
                )
            })
            .unwrap_or((
                None, None, None, None, None, None, None, None, None, None, None, None, None,
            ));

        // Parse geolocation
        let (country, continent, asn, as_name, as_domain) = {
            let geolocation = services.get_geolocation(&ip);
            (
                geolocation.country.clone(),
                geolocation.continent.clone(),
                geolocation.asn.clone(),
                geolocation.as_name.clone(),
                geolocation.as_domain.clone(),
            )
        };

        Ok(LogEntry {
            ip,
            identity: self.identity,
            user: self.user,
            timestamp: self.timestamp,
            method,
            path,
            extension,
            query,
            http_version,
            status_code: self.status_code,
            size: self.size,
            referer: self.referer,
            referer_origin,
            referer_path,
            referer_query,
            user_agent: self.user_agent,
            browser,
            browser_major,
            browser_minor,
            browser_patch,
            browser_patch_minor,
            os,
            os_major,
            os_minor,
            os_patch,
            os_patch_minor,
            device,
            brand,
            model,
            country,
            continent,
            asn,
            as_name,
            as_domain,
        })
    }
}

pub struct LogEntry {
    pub ip: IpAddr,
    pub identity: Option<String>,
    pub user: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub method: HttpMethod,
    pub path: String,
    pub extension: Option<String>,
    pub query: Option<String>,
    pub http_version: HttpVersion,
    pub status_code: u16,
    pub size: usize,
    pub referer: Option<Url>,
    pub referer_origin: Option<Origin>,
    pub referer_path: Option<String>,
    pub referer_query: Option<String>,
    pub user_agent: Option<String>,

    pub browser: Option<String>,
    pub browser_major: Option<u16>,
    pub browser_minor: Option<u16>,
    pub browser_patch: Option<u16>,
    pub browser_patch_minor: Option<u16>,

    pub os: Option<String>,
    pub os_major: Option<u16>,
    pub os_minor: Option<u16>,
    pub os_patch: Option<u16>,
    pub os_patch_minor: Option<u16>,

    pub device: Option<String>,
    pub brand: Option<String>,
    pub model: Option<String>,

    pub country: Option<String>,
    pub continent: Option<String>,
    pub asn: Option<String>,
    pub as_name: Option<String>,
    pub as_domain: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonLineRequest {
    remote_ip: String,
    remote_port: String,
    client_ip: String,
    proto: String,
    method: String,
    host: String,
    uri: String,
    headers: HashMap<String, [String; 1]>,
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonLine {
    pub msg: String,
    pub ts: f64,
    pub request: JsonLineRequest,
    bytes_read: u16,
    user_id: String,
    duration: f64,
    size: usize,
    status: u16,
    resp_headers: HashMap<String, Vec<String>>,
}

#[derive(Debug)]
pub struct LogError {
    filter: bool,
    line: String,
    error: String,
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid entry: {} ({})", self.line, self.error)
    }
}

impl Error for LogError {}
impl LogError {
    pub fn new(line: &str, error: &str) -> LogError {
        LogError {
            line: line.to_string(),
            error: error.to_string(),
            filter: false,
        }
    }
    pub fn new_filtered(line: &str) -> LogError {
        LogError {
            line: line.to_string(),
            error: String::from(""),
            filter: true,
        }
    }
    pub fn is_filtered(&self) -> bool {
        self.filter
    }
}

enum Patt<'a> {
    Char(char),
    Str(&'a str),
}

fn find(start: usize, line: &String, pattern: &Patt) -> Result<(String, usize), ParseError> {
    let pos = match pattern {
        Patt::Char(c) => line[start..].find(*c),
        Patt::Str(s) => line[start..].find(*s),
    };

    if let Some(pos) = pos {
        let end = start + pos;

        Ok((line[start..end].to_string(), end))
    } else {
        Err(ParseError::new())
    }
}

pub struct ParserServices<'a> {
    geolocations: HashMap<String, GeoLocation>,
    agents: HashMap<String, Agent>,
    agents_parser: Extractor<'a>,
    ip_reader: Reader<Vec<u8>>,
}

impl<'a> ParserServices<'a> {
    pub fn new() -> ParserServices<'a> {
        let regexes_bytes = include_bytes!("../resources/regexes.yaml");
        let regexes: Regexes = serde_yaml::from_slice(regexes_bytes).unwrap();
        let agents_parser = Extractor::try_from(regexes).unwrap();

        // IPinfo Lite (Free) -> https://ipinfo.io/dashboard/downloads
        let ipinfo = include_bytes!("../resources/ipinfo_lite.mmdb").to_vec();
        let ip_reader = Reader::from_source(ipinfo).unwrap();

        ParserServices {
            geolocations: HashMap::new(),
            agents: HashMap::new(),
            agents_parser,
            ip_reader,
        }
    }

    pub fn get_agent(&mut self, user_agent: &str) -> &Agent {
        if !self.agents.contains_key(user_agent) {
            let (ua, os, device) = self.agents_parser.extract(user_agent);
            let mut agent = Agent::from(ua, os, device);

            // Special case Mozlila (https://trunc.org/learning/the-mozlila-user-agent-bot)
            if user_agent.contains("Mozlila") {
                agent.device = Some(String::from("Spider"));
            }

            self.agents.insert(user_agent.to_string(), agent);
        }

        self.agents.get(user_agent).unwrap()
    }

    pub fn get_geolocation(&mut self, ip: &IpAddr) -> &GeoLocation {
        let key = ip.to_string();

        if !self.geolocations.contains_key(&key) {
            let geolocation = self.parse_geolocation(ip);
            self.geolocations.insert(key.clone(), geolocation);
        }

        self.geolocations.get(&key).unwrap()
    }

    fn parse_geolocation(&self, ip: &IpAddr) -> GeoLocation {
        let mut geolocation = GeoLocation::new();
        let info = self.ip_reader.lookup::<IpInfo>(ip.clone());
        if let Ok(info) = info {
            geolocation.continent = info.continent;
            geolocation.country = info.country;
            geolocation.asn = info.asn;
            geolocation.as_name = info.as_name;
            geolocation.as_domain = info.as_domain;
        }

        return geolocation;
    }
}

#[derive(serde::Deserialize)]
struct IpInfo {
    continent: Option<String>,
    country: Option<String>,
    asn: Option<String>,
    as_name: Option<String>,
    as_domain: Option<String>,
}

pub struct Agent {
    pub browser: Option<String>,
    pub browser_major: Option<u16>,
    pub browser_minor: Option<u16>,
    pub browser_patch: Option<u16>,
    pub browser_patch_minor: Option<u16>,

    pub os: Option<String>,
    pub os_major: Option<u16>,
    pub os_minor: Option<u16>,
    pub os_patch: Option<u16>,
    pub os_patch_minor: Option<u16>,

    pub device: Option<String>,
    pub brand: Option<String>,
    pub model: Option<String>,
}

impl Agent {
    pub fn new() -> Self {
        Agent {
            browser: None,
            browser_major: None,
            browser_minor: None,
            browser_patch: None,
            browser_patch_minor: None,
            os: None,
            os_major: None,
            os_minor: None,
            os_patch: None,
            os_patch_minor: None,
            device: None,
            brand: None,
            model: None,
        }
    }

    pub fn from(
        ua: Option<user_agent::ValueRef>,
        os: Option<os::ValueRef>,
        device: Option<device::ValueRef>,
    ) -> Self {
        let mut agent = Self::new();

        if let Some(value) = ua {
            agent.browser = Some(value.family.into_owned());
            agent.browser_major = value.major.and_then(|val| val.to_string().parse().ok());
            agent.browser_minor = value.minor.and_then(|val| val.to_string().parse().ok());
            agent.browser_patch = value.patch.and_then(|val| val.to_string().parse().ok());
            agent.browser_patch_minor = value
                .patch_minor
                .and_then(|val| val.to_string().parse().ok());
        }

        if let Some(value) = os {
            agent.os = Some(value.os.into_owned());
            agent.os_major = value.major.and_then(|val| val.to_string().parse().ok());
            agent.os_minor = value.minor.and_then(|val| val.to_string().parse().ok());
            agent.os_patch = value.patch.and_then(|val| val.to_string().parse().ok());
            agent.os_patch_minor = value
                .patch_minor
                .and_then(|val| val.to_string().parse().ok());
        }

        if let Some(value) = device {
            agent.device = Some(value.device.into_owned());
            agent.brand = value.brand.map(|val| val.to_string());
            agent.model = value.model.map(|val| val.to_string());
        }

        agent
    }
}

pub struct GeoLocation {
    pub country: Option<String>,
    pub continent: Option<String>,
    pub asn: Option<String>,
    pub as_name: Option<String>,
    pub as_domain: Option<String>,
}

impl GeoLocation {
    pub fn new() -> GeoLocation {
        GeoLocation {
            country: None,
            continent: None,
            asn: None,
            as_name: None,
            as_domain: None,
        }
    }
}
