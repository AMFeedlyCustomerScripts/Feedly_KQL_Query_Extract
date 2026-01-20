# Feedly KQL Query Extractor

Extract KQL (Kusto Query Language) hunting queries from Feedly Threat Intelligence streams for use in Microsoft Sentinel, Defender XDR, and other threat hunting platforms.

## Overview

This tool connects to Feedly's Threat Intelligence API to automatically extract KQL hunting queries from threat intel articles. Extracted queries include rich metadata for effective threat hunting.

### Use Cases

- **Microsoft Sentinel** - Import as Analytics Rules or Hunting Queries
- **Defender XDR** - Advanced Hunting library
- **Threat Hunt Playbooks** - Documented queries with context
- **Detection Engineering** - Backlog of queries to tune/deploy

## Requirements

- Python 3.8+
- Feedly API token (from Feedly TI subscription)
- Stream IDs containing threat hunting content

## Installation

1. Clone or download this repository

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure credentials (choose one method):

   **Option A: Environment variable**
   ```bash
   export FEEDLY_API_KEY="your_feedly_api_token"
   ```

   **Option B: .env file**
   ```bash
   echo 'FEEDLY_API_KEY="your_feedly_api_token"' > .env
   ```

   **Option C: Config file**
   ```bash
   cp config.yaml.template config.yaml
   # Edit config.yaml with your credentials
   ```

## Usage

### Basic Usage

```bash
# Extract queries to JSON (default)
python feedly_kql_extractor.py --stream "feed/..." --output queries.json

# Using config file
python feedly_kql_extractor.py --output queries.json
```

### Output Formats

```bash
# JSON - Full metadata, good for APIs and programmatic use
python feedly_kql_extractor.py --format json --output queries.json

# YAML - Human-readable, good for detection-as-code repos
python feedly_kql_extractor.py --format yaml --output queries.yaml

# Markdown - Documentation format with full context
python feedly_kql_extractor.py --format markdown --output queries.md

# CSV - Spreadsheet format for tracking and triage
python feedly_kql_extractor.py --format csv --output queries.csv

# KQL - Raw queries only, ready to paste into Sentinel/Defender
python feedly_kql_extractor.py --format kql --output queries.kql
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-c, --config` | Path to config file (default: config.yaml) |
| `--token` | Feedly API token (overrides config/env) |
| `--stream` | Stream ID (can be used multiple times) |
| `--since-hours` | Look back N hours (default: 24) |
| `--max-articles` | Max articles to process (default: 500) |
| `-o, --output` | Output file path |
| `-f, --format` | Output format: json, yaml, markdown, csv, kql |
| `--debug` | Enable debug output |

### Examples

```bash
# Extract from last 7 days
python feedly_kql_extractor.py --since-hours 168 --output weekly_queries.json

# Multiple streams
python feedly_kql_extractor.py \
  --stream "feed/https://feedly.com/f/feed1" \
  --stream "feed/https://feedly.com/f/feed2" \
  --output queries.json

# Generate markdown documentation
python feedly_kql_extractor.py --format markdown --output hunting_playbook.md
```

## Output Formats

### JSON Format
```json
{
  "extracted_at": "2025-01-20T12:00:00Z",
  "total_queries": 5,
  "queries": [
    {
      "query": "DeviceProcessEvents\n| where ...",
      "name": "DeviceProcessEvents_Suspicious_Activity",
      "description": "Detects suspicious process execution",
      "tables": ["DeviceProcessEvents"],
      "source_article_title": "Threat Analysis Report",
      "source_url": "https://...",
      "threat_actors": ["APT29"],
      "malware_families": ["Cobalt Strike"],
      "mitre_attacks": [{"id": "T1059", "label": "Command and Scripting Interpreter"}],
      "extraction_method": "indicatorsOfCompromise.huntingQueries"
    }
  ]
}
```

### Markdown Format
```markdown
## 1. DeviceProcessEvents_Suspicious_Activity

**Description:** Detects suspicious process execution

**Tables:** `DeviceProcessEvents`

**Threat Actors:** APT29

**MITRE ATT&CK:** T1059 (Command and Scripting Interpreter)

**Source:** [Threat Analysis Report](https://...)

​```kql
DeviceProcessEvents
| where ...
​```
```

### Raw KQL Format
```kql
// === DeviceProcessEvents_Suspicious_Activity ===
// Source: https://...
// Tables: DeviceProcessEvents
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| project TimeGenerated, DeviceName, ProcessCommandLine
```

## Extracted Metadata

Each query includes:

| Field | Description |
|-------|-------------|
| `query` | The KQL query text |
| `name` | Generated or extracted query name |
| `description` | What the query detects |
| `tables` | Data tables required (e.g., DeviceProcessEvents) |
| `source_article_title` | Original article title |
| `source_url` | Link to source article |
| `threat_actors` | Associated threat actors |
| `malware_families` | Associated malware |
| `mitre_attacks` | MITRE ATT&CK mappings |
| `extraction_method` | How the query was extracted |

## Extraction Methods

1. **indicatorsOfCompromise.huntingQueries** - Primary Feedly field for hunting queries
2. **linked.indicatorsOfCompromise.huntingQueries** - Queries from linked articles
3. **content_code_block** - Extracted from code blocks in article content

## Troubleshooting

### No queries found

1. Increase time range: `--since-hours 168` (1 week)
2. Verify stream contains hunting/KQL content
3. Run with `--debug` for detailed output

### Authentication errors

- Verify API token is valid
- Check token hasn't expired
- Ensure Feedly TI subscription access

## Security Notes

- **Never commit credentials** - config.yaml and .env are in .gitignore
- Store API tokens securely
- Use environment variables in CI/CD pipelines

## License

© 2025 Feedly, Inc. All rights reserved.

See script header for full disclaimer and terms of use.
