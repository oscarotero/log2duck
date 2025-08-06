# log2duck

Utility to parse access log files and create a Duckdb database with the
following columns.

| Column name          | Description                                       |
| -------------------- | ------------------------------------------------- |
| ip                   | Request's IP                                      |
| identity             | Identity value (usually `NULL`)                   |
| user                 | User's name (usually `NULL`)                      |
| timestamp            | Request's parsed time                             |
| method               | Enum with the request's method                    |
| path                 | Path of the URL                                   |
| extension            | Extension of the path                             |
| query                | Raw query params                                  |
| http_version         | Enum with the HTTP version                        |
| status_code          | Response's status code                            |
| size                 | The size of the response                          |
| referer              | Referer URL (from the HTTP headers)               |
| referer_origin       | Referer origin                                    |
| referer_path         | Referer path                                      |
| referer_query        | Referer raw query string                          |
| user_agent           | Raw user agent string                             |
| browser              | Detected browser name (from the user agent)       |
| browser_major        | Browser major version (from the user agent)       |
| browser_minor        | Browser minor version (from the user agent)       |
| browser_patch        | Browser patch version (from the user agent)       |
| browser_patch_minor  | Browser patch minor version (from the user agent) |
| os                   | Detected operating system (from the user agent)   |
| os_major             | OS major version (from the user agent)            |
| os_minor             | OS minor version (from the user agent)            |
| os_patch             | OS patch version (from the user agent)            |
| os_patch_minor       | OS patch minor version (from the user agent)      |
| device               | Detected device (from the user agent)             |
| brand                | Detected device brand (from the user agent)       |
| model                | Detected device model (from the user agent)       |
| country              | Detected country (from the ip)                    |
| continent            | Detected continent (from the ip)                  |
| asn                  | Detected ASN (from the ip)                        |
| as_name              | Name of the AS (from the ip)                      |
| as_domain            | Domain of the AS (from the ip)                    |

## Usage

Installation (macOS & Linux only):

```sh
curl -fsSL https://raw.githubusercontent.com/oscarotero/log2duck/refs/heads/main/install.sh | sh
```

Run the `log2duck` command with two arguments:

- The path to the log file
- The base URL of the site (used to resolve the URLs)

```sh
log2duck example.log https://example.com

# example.db  -> duckdb database
# example.err -> file with errors found
```

## Resources

- IP info: https://ipinfo.io/products/free-ip-database (login with GitHub)
- User agents: https://github.com/ua-parser/uap-core/blob/master/regexes.yaml
