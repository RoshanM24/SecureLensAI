"""
ZScaler Web Proxy Log Parser

Handles multiple log formats:
- JSON format (one JSON object per line)
- CSV format with headers
- Key-value pair format (field=value)
"""

import json
import csv
import io
from datetime import datetime
from typing import List, Dict, Any, Optional


class ZScalerParser:
    """Parser for ZScaler web proxy logs."""

    # Standard field names we normalize to
    FIELD_MAPPING = {
        "datetime": ["DateTime", "datetime", "Datetime", "time", "timestamp", "Time"],
        "user": ["User", "user", "Username", "username"],
        "client_ip": ["ClientIP", "clientip", "client_ip", "source_ip", "sourceip", "src_ip"],
        "client_public_ip": ["clientpublicIP", "clientPublicIP", "public_ip", "publicip"],
        "action": ["Action", "action"],
        "url": ["Url", "url", "URL"],
        "hostname": ["Hostname", "hostname", "host", "Host"],
        "url_category": ["urlcategory", "urlCategory", "category", "Category"],
        "status": ["Status", "status", "statuscode", "status_code", "http_status"],
        "request_method": ["requestmethod", "requestMethod", "method", "Method"],
        "user_agent": ["useragent", "userAgent", "user_agent", "User_Agent"],
        "transaction_size": ["transactionsize", "transactionSize", "bytes"],
        "request_size": ["requestsize", "requestSize", "request_bytes"],
        "response_size": ["responsesize", "responseSize", "response_bytes"],
        "threat_category": ["threatcategory", "threatCategory", "threat"],
        "threat_name": ["threatname", "threatName"],
        "location": ["Location", "location"],
        "department": ["Department", "department"],
        "protocol": ["Protocol", "protocol"],
        "server_ip": ["serverip", "server_ip", "destination_ip"],
        "referer_url": ["refererURL", "refererUrl", "referer", "referrer"],
    }

    def __init__(self):
        """Initialize the parser."""
        self.logs = []

    def parse(self, content: str) -> List[Dict[str, Any]]:
        """
        Parse log content and auto-detect format.

        Args:
            content: Raw log file content

        Returns:
            List of normalized log entry dictionaries

        Raises:
            ValueError: If format cannot be detected or parsing fails
        """
        content = content.strip()
        if not content:
            raise ValueError("Empty log file")

        # Try to detect format
        if self._looks_like_json(content):
            return self._parse_json(content)
        elif self._looks_like_csv(content):
            return self._parse_csv(content)
        else:
            return self._parse_key_value(content)

    def _looks_like_json(self, content: str) -> bool:
        """Check if content looks like JSON."""
        lines = content.split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith("{") or line.startswith("["):
                return True
        return False

    def _looks_like_csv(self, content: str) -> bool:
        """Check if content looks like CSV."""
        lines = content.split("\n")
        if len(lines) < 2:
            return False
        first_line = lines[0].strip()
        # CSV if first line has comma-separated values and second line matches
        return "," in first_line and not first_line.startswith("{")

    def _parse_json(self, content: str) -> List[Dict[str, Any]]:
        """Parse JSON format (one object per line)."""
        entries = []
        for line_num, line in enumerate(content.split("\n"), 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if isinstance(entry, dict):
                    normalized = self._normalize_fields(entry)
                    entries.append(normalized)
            except json.JSONDecodeError as e:
                print(f"[PARSER] Warning: Could not parse JSON on line {line_num}: {str(e)}")

        print(f"[PARSER] Parsed {len(entries)} JSON entries")
        return entries

    def _parse_csv(self, content: str) -> List[Dict[str, Any]]:
        """Parse CSV format with headers."""
        entries = []
        try:
            reader = csv.DictReader(io.StringIO(content))
            for row in reader:
                if row:
                    normalized = self._normalize_fields(row)
                    entries.append(normalized)

            print(f"[PARSER] Parsed {len(entries)} CSV entries")
            return entries
        except Exception as e:
            raise ValueError(f"Failed to parse CSV: {str(e)}")

    def _parse_key_value(self, content: str) -> List[Dict[str, Any]]:
        """Parse key=value format (tab or space separated)."""
        entries = []
        current_entry = {}

        for line_num, line in enumerate(content.split("\n"), 1):
            line = line.strip()

            # Skip empty lines
            if not line:
                if current_entry:
                    normalized = self._normalize_fields(current_entry)
                    entries.append(normalized)
                    current_entry = {}
                continue

            # Parse key=value pairs
            pairs = []
            if "\t" in line:
                pairs = line.split("\t")
            else:
                # Try splitting by spaces, but be careful with URLs
                pairs = line.split(" ")

            for pair in pairs:
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    current_entry[key.strip()] = value.strip()

        # Don't forget the last entry
        if current_entry:
            normalized = self._normalize_fields(current_entry)
            entries.append(normalized)

        print(f"[PARSER] Parsed {len(entries)} key-value entries")
        return entries

    def _normalize_fields(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize field names in a log entry.

        Maps various field name variations to standard names.
        Converts string numeric values to integers/floats where appropriate.
        """
        normalized = {}

        for standard_name, possible_names in self.FIELD_MAPPING.items():
            value = None
            # Find which field name is present in this entry
            for possible_name in possible_names:
                if possible_name in entry:
                    value = entry[possible_name]
                    break

            if value is not None:
                # Convert numeric strings
                if standard_name in ["status", "transaction_size", "request_size", "response_size"]:
                    try:
                        if isinstance(value, str):
                            value = int(value)
                    except (ValueError, TypeError):
                        pass

                normalized[standard_name] = value

        # Keep any fields we didn't recognize (for extensibility)
        entry_keys = set(entry.keys())
        known_keys = set()
        for possible_names in self.FIELD_MAPPING.values():
            known_keys.update(possible_names)

        for key in entry_keys:
            if key not in known_keys and key not in normalized:
                normalized[key] = entry[key]

        return normalized

    def validate_entry(self, entry: Dict[str, Any]) -> bool:
        """Check if an entry has minimum required fields."""
        # Minimal requirement: either datetime or some form of request info
        required_fields = {"datetime", "client_ip", "url"} if "datetime" in entry else {"client_ip", "url"}
        return bool(required_fields & set(entry.keys()))


def parse_log_file(file_content: str) -> List[Dict[str, Any]]:
    """
    Convenience function to parse log file content.

    Args:
        file_content: Raw log file content

    Returns:
        List of normalized log entries

    Raises:
        ValueError: If parsing fails
    """
    parser = ZScalerParser()
    return parser.parse(file_content)
