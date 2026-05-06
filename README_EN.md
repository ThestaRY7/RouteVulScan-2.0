README Version: [中文](README.md)

# RouteVulScan

RouteVulScan is a passive path vulnerability detection extension developed with the Burp Suite Montoya API.

Its goal is not large-scale directory brute forcing. Instead, while you test normal business traffic, it recursively extracts each path level, sends a small number of high-value probing requests according to rules, and determines matches through status codes and regular expressions. It can help identify common weaknesses such as configuration leaks, exposed debug interfaces, backup files, and legacy sensitive resources.

## Screenshots

<img width="1460" height="900" alt="image" src="https://github.com/user-attachments/assets/91f2c09b-bfd8-4c4b-a7c1-eeac29f196a0" />
<img width="1458" height="878" alt="image" src="https://github.com/user-attachments/assets/fcd82360-d563-4e7a-b1c7-754c8c13ca57" />

"Generation" refers to the current scan session's version number or cancellation marker.

In this extension, every click on "Cancel running scans" increments the internal `scanGeneration` by 1. The relevant code is in `BurpExtender.java` (line 165). The "Generation" value shown in the progress panel comes from the same counter; see `Config.java` (line 332).

Its meaning is simple:

- Generation 0: Initial state. "Cancel running scans" has not been executed yet.
- Generation 1: At least one cancellation has occurred. Subsequent new tasks belong to generation 1.
- Generation 2: Two cancellations have occurred, and so on.

This field is mainly used by the internal concurrent scanner to determine whether old tasks are stale. It is not the number of vulnerabilities or threads. For daily use, you can understand it as the current scan batch number.

## Project Source

This repository is a second-maintained version of the original project with compatibility fixes:

- Original GitHub repository: [F6JO/RouteVulScan](https://github.com/F6JO/RouteVulScan)

## What This Extension Does

- Passively scans requests and responses flowing through Burp without requiring you to maintain dictionaries or manually test directories one by one.
- Recursively probes each path level. For example, when visiting `/a/b/c`, it can continue checking `/`, `/a/`, `/a/b/`, and `/a/b/c/`.
- Matches status codes, keywords, and custom regular expressions through a YAML rule base to quickly discover issues that are low-volume but easy to miss.
- Supports sending requests to the extension from the context menu for active supplemental scanning, which is useful for focused checks on a single site.
- Supports rule grouping, enable/disable controls, request header inheritance, domain scanning, bypass scanning, result filtering, and history viewing.

## Use Cases

- During normal Web penetration testing, you want to uncover hidden APIs, sensitive files, and debug pages along the way.
- You do not want to run heavy brute-force scans, but you also do not want to miss high-value legacy resources under different path levels.
- You need an editable, extensible, and versionable local Burp rule base.

## Main Features

- Passive scanning: scans are triggered automatically when traffic passes through Burp.
- Active scanning: select a request from the context menu and send it to RouteVulScan.
- Rule engine: rules are stored in `Config_yaml.yaml` and support categories, enabled states, regular expressions, and status code ranges.
- Request template variables: rules can reference fields from the original request or response.
- Scan controls: supports thread count, host filtering, carrying request headers, domain scanning, and bypass scanning.
- Results panel: displays matched results, request packets, response packets, and supports filtering duplicate items with the same response length.

## Technical Choices

- Current-version first: uses Burp's official mainstream **Montoya API**.
- Official-recommendation first: uses **Swing + Montoya UI components** to build the extension interface.
- Production-ready target: uses **Maven + Shade Plugin** to package a fat jar that can be imported directly into Burp.
- Reason for dropping old approaches: no longer uses the legacy `IBurpExtender` / `ITab`, and no longer maintains the historical Gradle build chain.

## Requirements

- Burp Suite 2023.12.1 or later
- JDK 17
- Maven 3.9+

## Build

```bash
mvn clean package
```

After the build completes, the artifact is located at:

```bash
target/RouteVulScan-V2.0.2.jar
```

## Installation

Open the following in Burp Suite:

```text
Extender -> Extensions -> Add
```

Select `target/RouteVulScan-V2.0.2.jar` to load the extension.

## Usage

1. Load the extension in Burp.
2. On first startup, the extension will generate or use `Config_yaml.yaml` in the current working directory.
3. Enable the options you need on the configuration page, such as passive scanning, carrying request headers, and domain scanning.
4. Test the target site normally. The extension will automatically and recursively check each path level.
5. View matched records on the results page, along with the corresponding request and response.
6. To run supplemental scanning for a specific site, right-click a request and send it to RouteVulScan.

## Rule Description

The rule file is `Config_yaml.yaml`. Each rule can define:

- `type`: rule group
- `loaded`: whether the rule is enabled
- `name`: rule name
- `method`: request method
- `url`: path suffix
- `re`: matching regular expression
- `info`: match description
- `state`: status code; supports a single value, comma-separated values, or ranges

### Template Variables

Rules support referencing information from the current request or response:

```text
{{request.head.cookie}}
{{request.head.host.main}}
{{request.head.host.name}}
{{request.method}}
{{request.path}}
{{request.url}}
{{request.protocol}}
{{request.port}}
{{response.head.server}}
{{response.status}}
```

## Acknowledgements

- Original author: F6JO

[![Stargazers over time](https://starchart.cc/ThestaRY7/RouteVulScan-2.0.svg?variant=adaptive)](https://starchart.cc/ThestaRY7/RouteVulScan-2.0)

## Disclaimer

This tool is intended only for enterprise-owned security improvement, authorized security testing, and risk investigation within the scope granted by the asset owner. The purpose of this project is to help authorized parties improve the security protection capabilities of their own business systems. Before using this tool, any individual or organization must ensure that they have obtained legal authorization for the target system and comply with all applicable laws and regulations in their country or region.

Any direct or indirect problems, losses, disputes, or legal consequences caused by downloading, installing, distributing, using, or secondary development of this tool shall be borne solely by the user. The original author and project maintainers are not responsible for any unauthorized testing, attack behavior, or other improper use.
