"""
Rule-based anomaly detection engine.

Implements 10 rules for detecting security anomalies in web proxy logs.
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple
from collections import defaultdict, Counter


class RuleEngine:
    """Rule-based anomaly detection engine."""

    def __init__(self):
        """Initialize the rule engine."""
        self.rules_triggered = []
        self.stats = {}

    def analyze(self, entries: List[Dict[str, Any]]) -> Tuple[List[Dict], Dict]:
        """
        Analyze log entries against security rules.

        Args:
            entries: List of normalized log entries

        Returns:
            Tuple of (list of anomalies, statistics dict)
        """
        self.rules_triggered = []

        if not entries:
            return [], self._compute_stats(entries)

        print(f"[RULE_ENGINE] Analyzing {len(entries)} entries")

        # Run all rules
        self._check_high_request_frequency(entries)
        self._check_malicious_categories(entries)
        self._check_blocked_actions(entries)
        self._check_unusual_http_status(entries)
        self._check_large_data_transfer(entries)
        self._check_suspicious_user_agents(entries)
        self._check_off_hours_activity(entries)
        self._check_dns_tunneling(entries)
        self._check_repeated_failed_requests(entries)
        self._check_data_exfiltration(entries)

        # Compute statistics
        stats = self._compute_stats(entries)

        print(f"[RULE_ENGINE] Found {len(self.rules_triggered)} anomalies")
        return self.rules_triggered, stats

    def _check_high_request_frequency(self, entries: List[Dict[str, Any]]) -> None:
        """
        Rule 1: Single IP making >100 requests in 5 min window.
        Confidence: 0.85
        """
        # Group by IP and timestamp windows
        ip_requests = defaultdict(lambda: defaultdict(list))

        for idx, entry in enumerate(entries):
            ip = entry.get("client_ip")
            dt_str = entry.get("datetime")

            if not ip or not dt_str:
                continue

            try:
                dt = self._parse_datetime(dt_str)
                if dt:
                    # 5-minute window
                    window = dt.replace(second=0, microsecond=0) - timedelta(minutes=dt.minute % 5)
                    ip_requests[ip][window].append(idx)
            except:
                pass

        for ip, windows in ip_requests.items():
            for window, indices in windows.items():
                if len(indices) > 100:
                    self.rules_triggered.append({
                        "rule_id": "HIGH_FREQ_IP",
                        "rule_name": "High Request Frequency",
                        "description": f"IP {ip} made {len(indices)} requests in 5-minute window",
                        "confidence": 0.85,
                        "severity": "high",
                        "affected_entries": indices[:10],  # Sample first 10
                        "mitre_technique": "T1071",
                    })
                    print(f"[RULE_ENGINE] Rule triggered: HIGH_FREQ_IP - {ip} ({len(indices)} requests)")

    def _check_malicious_categories(self, entries: List[Dict[str, Any]]) -> None:
        """
        Rule 2: Known malicious URL/threat categories.
        Confidence: 0.95
        """
        malicious_categories = {
            "Malware", "Phishing", "Botnet", "Spyware", "Cryptomining", "Command and Control"
        }

        for idx, entry in enumerate(entries):
            url_cat = entry.get("url_category", "").strip()
            threat_cat = entry.get("threat_category", "").strip()

            if url_cat in malicious_categories or threat_cat in malicious_categories:
                category = url_cat or threat_cat
                self.rules_triggered.append({
                    "rule_id": "MALICIOUS_CATEGORY",
                    "rule_name": "Known Malicious Category",
                    "description": f"Detected {category} category in request to {entry.get('url', 'unknown')}",
                    "confidence": 0.95,
                    "severity": "critical",
                    "affected_entries": [idx],
                    "mitre_technique": "T1566",
                })
                print(f"[RULE_ENGINE] Rule triggered: MALICIOUS_CATEGORY - {category}")

    def _check_blocked_actions(self, entries: List[Dict[str, Any]]) -> None:
        """
        Rule 3: Blocked requests (potential policy violation).
        Confidence: 0.7
        """
        blocked_indices = []
        for idx, entry in enumerate(entries):
            action = entry.get("action", "").strip()
            if action.lower() == "blocked":
                blocked_indices.append(idx)

        if blocked_indices:
            self.rules_triggered.append({
                "rule_id": "BLOCKED_REQUESTS",
                "rule_name": "Blocked Requests",
                "description": f"Found {len(blocked_indices)} blocked requests (potential policy violations)",
                "confidence": 0.7,
                "severity": "medium",
                "affected_entries": blocked_indices[:20],
                "mitre_technique": "T1190",
            })
            print(f"[RULE_ENGINE] Rule triggered: BLOCKED_REQUESTS - {len(blocked_indices)} entries")

    def _check_unusual_http_status(self, entries: List[Dict[str, Any]]) -> None:
        """
        Rule 4: Unusual HTTP status codes (403, 401, 500, 502, 503).
        Confidence: 0.6
        """
        unusual_statuses = {403, 401, 500, 502, 503}
        affected = []

        for idx, entry in enumerate(entries):
            status = entry.get("status")
            if isinstance(status, str):
                try:
                    status = int(status)
                except ValueError:
                    continue

            if isinstance(status, int) and status in unusual_statuses:
                affected.append(idx)

        if affected:
            self.rules_triggered.append({
                "rule_id": "UNUSUAL_HTTP_STATUS",
                "rule_name": "Unusual HTTP Status Codes",
                "description": f"Found {len(affected)} requests with unusual status codes ({unusual_statuses})",
                "confidence": 0.6,
                "severity": "medium",
                "affected_entries": affected[:20],
                "mitre_technique": "T1190",
            })
            print(f"[RULE_ENGINE] Rule triggered: UNUSUAL_HTTP_STATUS - {len(affected)} entries")

    def _check_large_data_transfer(self, entries: List[Dict[str, Any]]) -> None:
        """
        Rule 5: Large data transfers (>50MB response or >100MB transaction).
        Confidence: 0.8
        """
        affected = []

        for idx, entry in enumerate(entries):
            response_size = entry.get("response_size")
            transaction_size = entry.get("transaction_size")

            # Convert to bytes if needed
            if isinstance(response_size, (int, float)) and response_size > 50 * 1024 * 1024:
                affected.append(idx)
            elif isinstance(transaction_size, (int, float)) and transaction_size > 100 * 1024 * 1024:
                affected.append(idx)

        if affected:
            self.rules_triggered.append({
                "rule_id": "LARGE_DATA_TRANSFER",
                "rule_name": "Large Data Transfer",
                "description": f"Detected {len(affected)} requests with unusually large data transfers",
                "confidence": 0.8,
                "severity": "high",
                "affected_entries": affected,
                "mitre_technique": "T1041",
            })
            print(f"[RULE_ENGINE] Rule triggered: LARGE_DATA_TRANSFER - {len(affected)} entries")

    def _check_suspicious_user_agents(self, entries: List[Dict[str, Any]]) -> None:
        """
        Rule 6: Suspicious user agents (curl, wget, python-requests, scanner, bot).
        Confidence: 0.7
        """
        suspicious_patterns = {"curl", "wget", "python-requests", "scanner", "bot"}
        affected = []

        for idx, entry in enumerate(entries):
            user_agent = entry.get("user_agent", "").lower()
            if any(pattern in user_agent for pattern in suspicious_patterns):
                affected.append(idx)

        if affected:
            self.rules_triggered.append({
                "rule_id": "SUSPICIOUS_USER_AGENT",
                "rule_name": "Suspicious User Agent",
                "description": f"Found {len(affected)} requests with suspicious user agents (automation tools)",
                "confidence": 0.7,
                "severity": "medium",
                "affected_entries": affected[:20],
                "mitre_technique": "T1071.001",
            })
            print(f"[RULE_ENGINE] Rule triggered: SUSPICIOUS_USER_AGENT - {len(affected)} entries")

    def _check_off_hours_activity(self, entries: List[Dict[str, Any]]) -> None:
        """
        Rule 7: Off-hours activity (00:00-05:00 local time).
        Confidence: 0.5
        """
        affected = []

        for idx, entry in enumerate(entries):
            dt_str = entry.get("datetime")
            if not dt_str:
                continue

            try:
                dt = self._parse_datetime(dt_str)
                if dt and 0 <= dt.hour < 5:  # 00:00-05:00
                    affected.append(idx)
            except:
                pass

        if len(affected) > len(entries) * 0.1:  # Only trigger if >10% of traffic
            self.rules_triggered.append({
                "rule_id": "OFF_HOURS_ACTIVITY",
                "rule_name": "Off-Hours Activity",
                "description": f"Detected {len(affected)} requests during off-hours (00:00-05:00)",
                "confidence": 0.5,
                "severity": "low",
                "affected_entries": affected[:20],
                "mitre_technique": "T1078",
            })
            print(f"[RULE_ENGINE] Rule triggered: OFF_HOURS_ACTIVITY - {len(affected)} entries")

    def _check_dns_tunneling(self, entries: List[Dict[str, Any]]) -> None:
        """
        Rule 8: DNS tunneling indicators (long hostnames or unusual TLDs).
        Confidence: 0.75
        """
        unusual_tlds = {"xyz", "tk", "ml", "ga", "cf", "download", "stream", "loan"}
        affected = []

        for idx, entry in enumerate(entries):
            hostname = entry.get("hostname", "")
            if not hostname:
                continue

            # Check for unusually long hostname (>50 chars)
            if len(hostname) > 50:
                affected.append(idx)
            # Check for unusual TLDs
            else:
                parts = hostname.split(".")
                if len(parts) > 0:
                    tld = parts[-1].lower()
                    if tld in unusual_tlds:
                        affected.append(idx)

        if affected:
            self.rules_triggered.append({
                "rule_id": "DNS_TUNNELING",
                "rule_name": "DNS Tunneling Indicators",
                "description": f"Found {len(affected)} requests with DNS tunneling indicators",
                "confidence": 0.75,
                "severity": "high",
                "affected_entries": affected[:20],
                "mitre_technique": "T1572",
            })
            print(f"[RULE_ENGINE] Rule triggered: DNS_TUNNELING - {len(affected)} entries")

    def _check_repeated_failed_requests(self, entries: List[Dict[str, Any]]) -> None:
        """
        Rule 9: Repeated failed requests (>5 4xx status codes per user in short window).
        Confidence: 0.8
        """
        user_failures = defaultdict(list)

        for idx, entry in enumerate(entries):
            user = entry.get("user")
            status = entry.get("status")

            if not user or not status:
                continue

            try:
                status = int(status) if isinstance(status, str) else status
                if 400 <= status < 500:  # 4xx errors
                    user_failures[user].append(idx)
            except (ValueError, TypeError):
                pass

        affected = []
        for user, indices in user_failures.items():
            if len(indices) > 5:
                affected.extend(indices)

        if affected:
            self.rules_triggered.append({
                "rule_id": "REPEATED_FAILED_REQUESTS",
                "rule_name": "Repeated Failed Requests",
                "description": f"Found {len(set(affected))} entries with repeated failed requests (>5 per user)",
                "confidence": 0.8,
                "severity": "medium",
                "affected_entries": affected[:20],
                "mitre_technique": "T1110",
            })
            print(f"[RULE_ENGINE] Rule triggered: REPEATED_FAILED_REQUESTS - {len(affected)} entries")

    def _check_data_exfiltration(self, entries: List[Dict[str, Any]]) -> None:
        """
        Rule 10: Data exfiltration pattern (large uploads to uncommon destinations).
        Confidence: 0.85
        """
        affected = []

        for idx, entry in enumerate(entries):
            request_size = entry.get("request_size")
            hostname = entry.get("hostname", "")

            if isinstance(request_size, (int, float)) and request_size > 10 * 1024 * 1024:  # >10MB
                # Check if it's an uncommon destination (not well-known cloud/storage)
                common_hosts = {
                    "dropbox.com", "google.com", "microsoft.com", "amazon.com",
                    "github.com", "gitlab.com", "slack.com", "teams.microsoft.com"
                }
                is_common = any(host in hostname.lower() for host in common_hosts)

                if not is_common and hostname:  # Uncommon destination
                    affected.append(idx)

        if affected:
            self.rules_triggered.append({
                "rule_id": "DATA_EXFILTRATION",
                "rule_name": "Data Exfiltration Pattern",
                "description": f"Detected {len(affected)} large uploads to uncommon destinations",
                "confidence": 0.85,
                "severity": "critical",
                "affected_entries": affected,
                "mitre_technique": "T1567",
            })
            print(f"[RULE_ENGINE] Rule triggered: DATA_EXFILTRATION - {len(affected)} entries")

    def _compute_stats(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compute statistics from log entries."""
        if not entries:
            return {}

        # Basic counts
        ips = set()
        users = set()
        urls = []
        statuses = Counter()
        actions = Counter()
        url_categories = Counter()
        threat_categories = Counter()
        hourly_traffic = defaultdict(int)

        for entry in entries:
            if "client_ip" in entry:
                ips.add(entry["client_ip"])
            if "user" in entry:
                users.add(entry["user"])
            if "url" in entry:
                urls.append(entry["url"])
            if "status" in entry:
                try:
                    status = int(entry["status"]) if isinstance(entry["status"], str) else entry["status"]
                    statuses[status] += 1
                except (ValueError, TypeError):
                    pass
            if "action" in entry:
                actions[entry["action"]] += 1
            if "url_category" in entry and entry["url_category"]:
                url_categories[entry["url_category"]] += 1
            if "threat_category" in entry and entry["threat_category"]:
                threat_categories[entry["threat_category"]] += 1

            # Hourly traffic
            dt_str = entry.get("datetime")
            if dt_str:
                try:
                    dt = self._parse_datetime(dt_str)
                    if dt:
                        hour_key = dt.strftime("%Y-%m-%d %H:00")
                        hourly_traffic[hour_key] += 1
                except:
                    pass

        return {
            "total_events": len(entries),
            "unique_ips": len(ips),
            "unique_users": len(users),
            "unique_urls": len(set(urls)),
            "top_ips": [{"ip": ip, "count": count} for ip, count in Counter([e.get("client_ip") for e in entries if e.get("client_ip")]).most_common(10)],
            "top_urls": [{"url": url, "count": count} for url, count in Counter(urls).most_common(10)],
            "action_distribution": dict(actions),
            "status_distribution": dict(statuses),
            "top_categories": [{"category": cat, "count": count} for cat, count in url_categories.most_common(10)],
            "top_threat_categories": [{"category": cat, "count": count} for cat, count in threat_categories.most_common(10)],
            "traffic_over_time": [{"hour": t, "count": count} for t, count in sorted(hourly_traffic.items())],
        }

    def _parse_datetime(self, dt_str: str) -> datetime:
        """Try to parse datetime string in multiple formats."""
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%f",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(dt_str.split(".")[0], fmt)
            except ValueError:
                continue

        return None
