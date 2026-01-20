#!/usr/bin/env python3
"""
Feedly KQL Query Extractor

Extracts KQL (Kusto Query Language) hunting queries from Feedly Threat
Intelligence streams for use in Microsoft Sentinel, Defender XDR, and
other threat hunting platforms.

Usage:
    # Basic extraction
    python feedly_kql_extractor.py --stream "feed/..." --output queries.json

    # Different output formats
    python feedly_kql_extractor.py --stream "feed/..." --format json --output queries.json
    python feedly_kql_extractor.py --stream "feed/..." --format yaml --output queries.yaml
    python feedly_kql_extractor.py --stream "feed/..." --format markdown --output queries.md
    python feedly_kql_extractor.py --stream "feed/..." --format csv --output queries.csv
    python feedly_kql_extractor.py --stream "feed/..." --format kql --output queries.kql

© 2025 Feedly, Inc. All rights reserved.

DISCLAIMERS. THE API SCRIPTS ARE PROVIDED "AS IS" FOR YOUR INTERNAL BUSINESS
USE ONLY. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE API SCRIPTS
IS WITH YOU. YOU AGREE THAT YOUR USE OF THE API SCRIPTS WILL BE AT YOUR SOLE
RISK. TO THE FULLEST EXTENT PERMITTED BY LAW, FEEDLY DISCLAIMS ALL WARRANTIES,
EXPRESS OR IMPLIED, IN CONNECTION WITH THE API SCRIPTS AND YOUR USE THEREOF,
INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. FEEDLY MAKES NO
WARRANTIES OR REPRESENTATIONS ABOUT THE ACCURACY OR COMPLETENESS OF THE API
SCRIPTS AND NO REPRESENTATIONS THAT THE API SCRIPTS ARE NOT OTHERWISE
ENCUMBERED BY ANY THIRD PARTY LICENSE, INCLUDING ANY OPEN-SOURCE LICENSE.
FEEDLY ASSUMES NO LIABILITY OR RESPONSIBILITY FOR ANY: (1) ERRORS, MISTAKES,
OR INACCURACIES; (2) PERSONAL INJURY OR PROPERTY DAMAGE, OF ANY NATURE
WHATSOEVER, RESULTING FROM YOUR USE OF THE API SCRIPTS; (3) ANY UNAUTHORIZED
ACCESS TO OR USE OF API SCRIPTS; (4) ANY INTERRUPTION OR CESSATION OF
TRANSMISSION TO OR FROM THE API SCRIPTS; (5) ANY BUGS, VIRUSES, TROJAN HORSES,
OR THE LIKE WHICH MAY BE TRANSMITTED TO OR THROUGH THE API SCRIPTS BY ANY
THIRD PARTY; OR (6) ANY ERRORS OR OMISSIONS IN THE API SCRIPTS OR FOR ANY LOSS
OR DAMAGE OF ANY KIND INCURRED AS A RESULT OF THE USE OF THE API SCRIPTS.

LIMITATION OF LIABILITY. IN NO EVENT SHALL FEEDLY BE LIABLE FOR ANY DAMAGES.
FURTHER, IN NO EVENT SHALL FEEDLY BE LIABLE FOR ANY CONSEQUENTIAL, INCIDENTAL
OR INDIRECT DAMAGES, INCLUDING, WITHOUT LIMITATION, ANY LOSS OF DATA, OR LOSS
OF PROFITS OR LOST SAVINGS, ARISING OUT OF USE OF OR INABILITY TO USE THE
LICENSED PRODUCT, EVEN IF FEEDLY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
DAMAGES, OR FOR ANY CLAIM BY ANY THIRD PARTY.

YOU ACKNOWLEDGE THAT YOU HAVE READ AND UNDERSTAND THESE TERMS AND AGREE TO BE
BOUND BY THEM. YOU FURTHER AGREE THAT THESE TERMS ARE THE COMPLETE AND
EXCLUSIVE STATEMENT OF THE AGREEMENT BETWEEN YOU AND FEEDLY FOR THE USE OF THE
API SCRIPTS, AND THESE TERMS SUPERSEDE ANY PRIOR AGREEMENT, ORAL OR WRITTEN,
AND ANY OTHER COMMUNICATIONS RELATING TO THE SUBJECT MATTER HEREOF.
"""

# =============================================================================
# IMPORTS
# =============================================================================

import argparse
import csv
import hashlib
import io
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from html import unescape
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library is required. Install with: pip install requests")
    sys.exit(1)

try:
    import yaml
except ImportError:
    yaml = None
    print("WARNING: PyYAML not installed. YAML output and config file loading disabled.")
    print("         Install with: pip install pyyaml")


# =============================================================================
# CONFIGURATION
# =============================================================================

# API Configuration
BASE_URL = "https://api.feedly.com"
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds
RATE_LIMIT_DELAY = 1  # seconds between API calls
REQUEST_TIMEOUT = 30  # seconds

# KQL Detection Patterns
KQL_TABLES = [
    'SecurityEvent', 'SecurityAlert', 'SecurityIncident',
    'DeviceProcessEvents', 'DeviceNetworkEvents', 'DeviceFileEvents',
    'DeviceRegistryEvents', 'DeviceLogonEvents', 'DeviceImageLoadEvents',
    'DeviceEvents', 'DeviceInfo', 'DeviceTvmSoftwareInventory',
    'SigninLogs', 'AuditLogs', 'AADSignInEventsBeta',
    'OfficeActivity', 'EmailEvents', 'EmailAttachmentInfo', 'EmailUrlInfo',
    'IdentityLogonEvents', 'IdentityQueryEvents', 'IdentityDirectoryEvents',
    'CloudAppEvents', 'AlertEvidence', 'AlertInfo',
    'ThreatIntelligenceIndicator', 'Heartbeat', 'Syslog', 'CommonSecurityLog'
]

KQL_OPERATORS = [
    '| where', '| project', '| summarize', '| extend', '| join',
    '| union', '| parse', '| render', '| sort', '| order by',
    '| take', '| limit', '| count', '| distinct', '| top',
    '| mv-expand', '| mv-apply', '| make-series', '| serialize'
]

KQL_FUNCTIONS = [
    'ago(', 'datetime(', 'now(', 'tostring(', 'toint(', 'tolong(',
    'parse_json(', 'todynamic(', 'extract(', 'strcat(', 'split(',
    'iff(', 'case(', 'coalesce(', 'has_any(', 'has_all(',
    'contains', 'startswith', 'endswith', 'matches regex'
]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def load_api_key() -> str:
    """
    Load API key from environment variable or .env file.
    Priority: FEEDLY_API_KEY env var > .env file > empty string
    """
    api_key = os.environ.get("FEEDLY_API_KEY")
    if api_key:
        return api_key

    env_locations = [
        os.path.join(os.getcwd(), ".env"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
    ]

    for env_path in env_locations:
        if os.path.exists(env_path):
            try:
                with open(env_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("FEEDLY_API_KEY=") and not line.startswith("#"):
                            key = line.split("=", 1)[1].strip()
                            if (key.startswith('"') and key.endswith('"')) or \
                               (key.startswith("'") and key.endswith("'")):
                                key = key[1:-1]
                            if key:
                                return key
            except Exception:
                pass

    return ""


def _request(
    session: requests.Session,
    method: str,
    endpoint: str,
    data=None,
    params=None,
    retries: int = MAX_RETRIES
) -> Optional[requests.Response]:
    """Make an API request with retry logic and rate limiting."""
    url = f"{BASE_URL}{endpoint}" if endpoint.startswith("/") else endpoint

    for attempt in range(retries):
        try:
            response = session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=REQUEST_TIMEOUT
            )

            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", RETRY_DELAY * (attempt + 1)))
                print(f"  Rate limited. Waiting {retry_after}s...")
                time.sleep(retry_after)
                continue

            if response.status_code >= 500:
                if attempt < retries - 1:
                    wait_time = RETRY_DELAY * (attempt + 1)
                    print(f"  Server error {response.status_code}. Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                    continue

            return response

        except requests.exceptions.RequestException as e:
            if attempt < retries - 1:
                wait_time = RETRY_DELAY * (attempt + 1)
                print(f"  Connection error: {e}. Retrying in {wait_time}s...")
                time.sleep(wait_time)
                continue
            raise

    return None


def strip_html(html_content: str) -> str:
    """Remove HTML tags and decode entities."""
    if not html_content:
        return ""
    clean = re.sub(r'<[^>]+>', ' ', html_content)
    clean = unescape(clean)
    clean = re.sub(r'\s+', ' ', clean).strip()
    return clean


def extract_code_blocks(html_content: str) -> List[str]:
    """Extract content from <code> and <pre> blocks."""
    blocks = []
    if not html_content:
        return blocks

    pre_pattern = r'<pre[^>]*>(.*?)</pre>'
    for match in re.findall(pre_pattern, html_content, re.DOTALL | re.IGNORECASE):
        blocks.append(strip_html(match))

    code_pattern = r'<code[^>]*>(.*?)</code>'
    for match in re.findall(code_pattern, html_content, re.DOTALL | re.IGNORECASE):
        blocks.append(strip_html(match))

    return blocks


def is_kql_query(text: str) -> bool:
    """Determine if text is likely a KQL query."""
    if not text or len(text) < 20:
        return False

    text_lower = text.lower()
    score = 0

    # Check for KQL table names
    for table in KQL_TABLES:
        if table.lower() in text_lower:
            score += 10

    # Check for pipe operators
    for op in KQL_OPERATORS:
        if op.lower() in text_lower:
            score += 5

    # Check for KQL functions
    for func in KQL_FUNCTIONS:
        if func.lower() in text_lower:
            score += 3

    # Pipe count
    pipe_count = text.count('|')
    if pipe_count >= 2:
        score += min(pipe_count * 2, 10)

    return score >= 15


def extract_kql_tables(query: str) -> List[str]:
    """Extract table names referenced in a KQL query."""
    tables_found = []
    for table in KQL_TABLES:
        if re.search(rf'\b{table}\b', query, re.IGNORECASE):
            tables_found.append(table)
    return tables_found


def generate_query_name(query: str, source_title: str) -> str:
    """Generate a descriptive name for a query."""
    tables = extract_kql_tables(query)
    if tables:
        table_part = tables[0]
    else:
        table_part = "Query"

    # Clean source title
    clean_title = re.sub(r'[^\w\s-]', '', source_title)[:30].strip()
    clean_title = re.sub(r'\s+', '_', clean_title)

    return f"{table_part}_{clean_title}"


# =============================================================================
# API FUNCTIONS
# =============================================================================

def get_stream_contents(
    session: requests.Session,
    stream_id: str,
    count: int = 100,
    newer_than: Optional[int] = None,
    continuation: Optional[str] = None
) -> Dict[str, Any]:
    """Fetch articles from a Feedly stream."""
    params = {
        "streamId": stream_id,
        "count": min(count, 100)
    }

    if newer_than:
        params["newerThan"] = newer_than
    if continuation:
        params["continuation"] = continuation

    response = _request(
        session=session,
        method="GET",
        endpoint="/v3/streams/contents",
        params=params
    )

    if response is None:
        return {"items": []}

    response.raise_for_status()
    return response.json()


# =============================================================================
# KQL EXTRACTION FUNCTIONS
# =============================================================================

def extract_kql_from_article(
    session: requests.Session,
    article: Dict[str, Any],
    debug: bool = False
) -> List[Dict[str, Any]]:
    """Extract KQL queries from a Feedly article."""
    queries = []
    article_id = article.get("id", "unknown")
    article_title = article.get("title", "Unknown Title")
    article_url = article.get("canonicalUrl") or article.get("originId", "")
    published = article.get("published", 0)

    # Extract related threat info
    entities = article.get("entities", [])
    threat_actors = []
    malware_families = []
    for entity in entities:
        if isinstance(entity, dict):
            entity_type = entity.get("type", "")
            entity_label = entity.get("label", "")
            if "threat-actor" in entity_type.lower() or "actor" in entity_type.lower():
                threat_actors.append(entity_label)
            elif "malware" in entity_type.lower():
                malware_families.append(entity_label)

    # Extract MITRE ATT&CK if available
    mitre_attacks = []
    for entity in entities:
        if isinstance(entity, dict):
            if "attack-pattern" in entity.get("type", "").lower() or \
               "mitre" in entity.get("type", "").lower():
                mitre_attacks.append({
                    "id": entity.get("id", ""),
                    "label": entity.get("label", "")
                })

    # Common metadata for all queries from this article
    base_metadata = {
        "source_article_id": article_id,
        "source_article_title": article_title,
        "source_url": article_url,
        "published_timestamp": published,
        "threat_actors": threat_actors,
        "malware_families": malware_families,
        "mitre_attacks": mitre_attacks
    }

    # Method 1: Extract from indicatorsOfCompromise.huntingQueries (PRIMARY)
    ioc_data = article.get("indicatorsOfCompromise", {})
    hunting_queries = ioc_data.get("huntingQueries", []) if isinstance(ioc_data, dict) else []

    if hunting_queries:
        print(f"  Found {len(hunting_queries)} hunting queries via indicatorsOfCompromise")
        for i, hq in enumerate(hunting_queries):
            if isinstance(hq, dict):
                query_text = hq.get("query", "")
                query_desc = hq.get("description", "")
                query_name = hq.get("name", "")

                if query_text and is_kql_query(query_text):
                    queries.append({
                        "query": query_text.strip(),
                        "name": query_name or generate_query_name(query_text, article_title),
                        "description": query_desc or f"Hunting query from: {article_title}",
                        "tables": extract_kql_tables(query_text),
                        "extraction_method": "indicatorsOfCompromise.huntingQueries",
                        **base_metadata
                    })

    # Method 2: Check linked articles for hunting queries
    linked_articles = article.get("linked", [])
    for linked in linked_articles:
        if isinstance(linked, dict):
            linked_ioc = linked.get("indicatorsOfCompromise", {})
            linked_queries = linked_ioc.get("huntingQueries", []) if isinstance(linked_ioc, dict) else []

            for hq in linked_queries:
                if isinstance(hq, dict):
                    query_text = hq.get("query", "")
                    if query_text and is_kql_query(query_text):
                        queries.append({
                            "query": query_text.strip(),
                            "name": hq.get("name", "") or generate_query_name(query_text, article_title),
                            "description": hq.get("description", "") or f"Linked hunting query from: {article_title}",
                            "tables": extract_kql_tables(query_text),
                            "extraction_method": "linked.indicatorsOfCompromise.huntingQueries",
                            **base_metadata
                        })

    # Method 3: Extract from article content (code blocks)
    content_html = article.get("content", {}).get("content", "") or \
                   article.get("summary", {}).get("content", "") or \
                   article.get("fullContent", "")

    if content_html:
        code_blocks = extract_code_blocks(content_html)
        for block in code_blocks:
            if is_kql_query(block) and len(block) > 30:
                # Avoid duplicates
                block_hash = hashlib.md5(block.encode()).hexdigest()
                existing_hashes = [hashlib.md5(q["query"].encode()).hexdigest() for q in queries]
                if block_hash not in existing_hashes:
                    queries.append({
                        "query": block.strip(),
                        "name": generate_query_name(block, article_title),
                        "description": f"Extracted from article: {article_title}",
                        "tables": extract_kql_tables(block),
                        "extraction_method": "content_code_block",
                        **base_metadata
                    })

        if queries and debug:
            print(f"  Extracted {len([q for q in queries if q['extraction_method'] == 'content_code_block'])} queries from code blocks")

    return queries


def fetch_kql_queries(
    api_token: str,
    stream_ids: List[str],
    since_hours: int = 24,
    max_articles: int = 500,
    debug: bool = False
) -> List[Dict[str, Any]]:
    """Fetch all KQL queries from configured streams."""

    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json"
    })

    print("\n" + "="*70)
    print("Feedly KQL Query Extractor")
    print("="*70)

    # Verify connection
    profile_resp = _request(session, "GET", "/v3/profile")
    if profile_resp is None:
        print("ERROR: Failed to connect to Feedly API")
        return []

    if profile_resp.status_code == 200:
        print(f"Connected as: {profile_resp.json().get('email', 'unknown')}")
    elif profile_resp.status_code == 401:
        print("ERROR: Invalid API token (401 Unauthorized)")
        return []
    else:
        print(f"WARNING: Profile check returned {profile_resp.status_code}")

    all_queries = []
    seen_hashes = set()
    newer_than = int((datetime.now(timezone.utc) - timedelta(hours=since_hours)).timestamp() * 1000)

    for stream_id in stream_ids:
        print(f"\nProcessing stream: {stream_id[:60]}...")

        articles_processed = 0
        articles_with_kql = 0
        continuation = None

        while articles_processed < max_articles:
            try:
                data = get_stream_contents(
                    session=session,
                    stream_id=stream_id,
                    count=100,
                    newer_than=newer_than,
                    continuation=continuation
                )
            except requests.exceptions.HTTPError as e:
                if hasattr(e, 'response') and e.response.status_code == 404:
                    print(f"ERROR: Stream not found: {stream_id}")
                else:
                    print(f"ERROR: Error fetching stream: {e}")
                break
            except requests.exceptions.RequestException as e:
                print(f"ERROR: Connection error: {e}")
                break

            items = data.get("items", [])
            if not items:
                print("  No more articles in this time range")
                break

            for article in items:
                title = article.get("title", "No title")[:50]

                # Check for hunting queries indicator
                ioc_data = article.get("indicatorsOfCompromise", {})
                has_hunting_queries = bool(ioc_data.get("huntingQueries")) if isinstance(ioc_data, dict) else False

                # Check topics for hunting-related tags
                topics = article.get("commonTopics", [])
                has_hunting_topic = any(
                    "hunting" in t.get("label", "").lower() or
                    "kql" in t.get("label", "").lower() or
                    "kusto" in t.get("label", "").lower()
                    for t in topics if isinstance(t, dict)
                )

                if has_hunting_queries or has_hunting_topic:
                    print(f"\nProcessing: {title}...")
                    queries = extract_kql_from_article(session, article, debug=debug)

                    if queries:
                        articles_with_kql += 1
                        for query in queries:
                            query_hash = hashlib.md5(query["query"].encode()).hexdigest()
                            if query_hash not in seen_hashes:
                                seen_hashes.add(query_hash)
                                query["content_hash"] = query_hash
                                all_queries.append(query)

                time.sleep(RATE_LIMIT_DELAY)

            articles_processed += len(items)
            continuation = data.get("continuation")

            if not continuation:
                break

        print(f"\n  Processed {articles_processed} articles")
        print(f"  Found {articles_with_kql} articles with KQL queries")

    return all_queries


# =============================================================================
# OUTPUT FORMATTERS
# =============================================================================

def format_json(queries: List[Dict[str, Any]]) -> str:
    """Format queries as JSON."""
    output = {
        "extracted_at": datetime.now(timezone.utc).isoformat(),
        "total_queries": len(queries),
        "queries": queries
    }
    return json.dumps(output, indent=2, default=str)


def format_yaml(queries: List[Dict[str, Any]]) -> str:
    """Format queries as YAML."""
    if yaml is None:
        raise ImportError("PyYAML required for YAML output. Install with: pip install pyyaml")

    output = {
        "extracted_at": datetime.now(timezone.utc).isoformat(),
        "total_queries": len(queries),
        "queries": queries
    }
    return yaml.dump(output, default_flow_style=False, sort_keys=False, allow_unicode=True)


def format_markdown(queries: List[Dict[str, Any]]) -> str:
    """Format queries as Markdown documentation."""
    lines = [
        "# KQL Hunting Queries",
        "",
        f"Extracted: {datetime.now(timezone.utc).isoformat()}",
        f"Total Queries: {len(queries)}",
        "",
        "---",
        ""
    ]

    for i, q in enumerate(queries, 1):
        lines.append(f"## {i}. {q.get('name', 'Unnamed Query')}")
        lines.append("")

        if q.get("description"):
            lines.append(f"**Description:** {q['description']}")
            lines.append("")

        if q.get("tables"):
            lines.append(f"**Tables:** `{'`, `'.join(q['tables'])}`")
            lines.append("")

        if q.get("threat_actors"):
            lines.append(f"**Threat Actors:** {', '.join(q['threat_actors'])}")
            lines.append("")

        if q.get("malware_families"):
            lines.append(f"**Malware:** {', '.join(q['malware_families'])}")
            lines.append("")

        if q.get("mitre_attacks"):
            mitre_str = ", ".join([f"{m['id']} ({m['label']})" for m in q['mitre_attacks'] if m.get('id')])
            if mitre_str:
                lines.append(f"**MITRE ATT&CK:** {mitre_str}")
                lines.append("")

        if q.get("source_url"):
            lines.append(f"**Source:** [{q.get('source_article_title', 'Link')}]({q['source_url']})")
            lines.append("")

        lines.append("```kql")
        lines.append(q.get("query", ""))
        lines.append("```")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def format_csv(queries: List[Dict[str, Any]]) -> str:
    """Format queries as CSV."""
    output = io.StringIO()
    fieldnames = [
        'name', 'description', 'tables', 'query',
        'source_article_title', 'source_url',
        'threat_actors', 'malware_families',
        'extraction_method', 'content_hash'
    ]

    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()

    for q in queries:
        row = q.copy()
        row['tables'] = '; '.join(q.get('tables', []))
        row['threat_actors'] = '; '.join(q.get('threat_actors', []))
        row['malware_families'] = '; '.join(q.get('malware_families', []))
        # Escape newlines in query for CSV
        row['query'] = q.get('query', '').replace('\n', '\\n')
        writer.writerow(row)

    return output.getvalue()


def format_kql(queries: List[Dict[str, Any]]) -> str:
    """Format as raw KQL queries only."""
    lines = [
        "// KQL Hunting Queries",
        f"// Extracted: {datetime.now(timezone.utc).isoformat()}",
        f"// Total: {len(queries)} queries",
        ""
    ]

    for q in queries:
        lines.append(f"// === {q.get('name', 'Query')} ===")
        lines.append(f"// Source: {q.get('source_url', 'unknown')}")
        if q.get('tables'):
            lines.append(f"// Tables: {', '.join(q['tables'])}")
        lines.append(q.get("query", ""))
        lines.append("")

    return "\n".join(lines)


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Extract KQL hunting queries from Feedly Threat Intelligence streams"
    )
    parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)"
    )
    parser.add_argument(
        "--token",
        help="Feedly API token (overrides config file and env var)"
    )
    parser.add_argument(
        "--stream",
        action="append",
        dest="streams",
        help="Stream ID to fetch from (can be specified multiple times)"
    )
    parser.add_argument(
        "--since-hours",
        type=int,
        default=24,
        help="Fetch articles from the last N hours (default: 24)"
    )
    parser.add_argument(
        "--max-articles",
        type=int,
        default=500,
        help="Maximum articles to process (default: 500)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "yaml", "markdown", "csv", "kql"],
        default="json",
        help="Output format (default: json)"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output"
    )

    args = parser.parse_args()

    # Get API token
    api_token = args.token or load_api_key()
    stream_ids = args.streams or []

    # Load from config file
    if (not api_token or not stream_ids) and yaml:
        config_path = args.config
        if os.path.exists(config_path):
            print(f"Loading configuration from {config_path}...")
            try:
                with open(config_path) as f:
                    config = yaml.safe_load(f)
                if not api_token:
                    api_token = config.get("feedly", {}).get("api_token")
                if not stream_ids:
                    stream_ids = config.get("feedly", {}).get("stream_ids", [])
            except Exception as e:
                print(f"WARNING: Failed to load config file: {e}")

    # Validate
    if not api_token:
        print("\nERROR: Feedly API token required")
        print("\nProvide token via:")
        print("  1. --token YOUR_TOKEN")
        print("  2. FEEDLY_API_KEY environment variable")
        print("  3. config.yaml file")
        print("  4. .env file")
        sys.exit(1)

    if not stream_ids:
        print("\nERROR: At least one stream ID required")
        print("\nProvide stream IDs via:")
        print("  1. --stream STREAM_ID")
        print("  2. config.yaml file")
        sys.exit(1)

    # Fetch queries
    queries = fetch_kql_queries(
        api_token=api_token,
        stream_ids=stream_ids,
        since_hours=args.since_hours,
        max_articles=args.max_articles,
        debug=args.debug
    )

    # Results
    print("\n" + "="*70)
    print("RESULTS")
    print("="*70)
    print(f"Total unique KQL queries found: {len(queries)}")

    if not queries:
        print("\nNo KQL queries found.")
        print("\nTry:")
        print("  - Increasing --since-hours to look further back")
        print("  - Verifying the stream contains hunting query content")
        return

    # Group by extraction method
    by_method = {}
    for q in queries:
        method = q.get("extraction_method", "unknown")
        by_method[method] = by_method.get(method, 0) + 1

    print("\nExtraction methods:")
    for method, count in by_method.items():
        print(f"  - {method}: {count} queries")

    # Group by tables
    all_tables = set()
    for q in queries:
        all_tables.update(q.get("tables", []))

    if all_tables:
        print(f"\nTables referenced: {', '.join(sorted(all_tables))}")

    # Format output
    formatters = {
        "json": format_json,
        "yaml": format_yaml,
        "markdown": format_markdown,
        "csv": format_csv,
        "kql": format_kql
    }

    try:
        output_text = formatters[args.format](queries)
    except ImportError as e:
        print(f"\nERROR: {e}")
        sys.exit(1)

    # Output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output_text)
        print(f"\nQueries written to: {args.output}")
    else:
        print("\n" + "-"*70)
        print("PREVIEW (first 2 queries):")
        print("-"*70)
        for q in queries[:2]:
            print(f"\nName: {q.get('name', 'Unnamed')}")
            print(f"Tables: {', '.join(q.get('tables', []))}")
            print(f"Source: {q.get('source_article_title', 'Unknown')[:50]}")
            query_preview = q.get('query', '')[:300]
            print(f"Query: {query_preview}...")

        if len(queries) > 2:
            print(f"\n... and {len(queries) - 2} more queries")

        print(f"\nUse --output FILE --format {args.format} to save all queries")


if __name__ == "__main__":
    main()
