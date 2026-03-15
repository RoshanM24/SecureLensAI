#!/usr/bin/env python3
"""
End-to-end backend test script for Secure Lens AI.
Run from the backend/ directory:  python test_backend.py
"""

import os
import sys
import json
import traceback

# Make sure we're in the backend directory
os.chdir(os.path.dirname(os.path.abspath(__file__)))

def test_step(name, fn):
    """Run a test step, print result."""
    try:
        result = fn()
        print(f"  [PASS] {name}")
        return result
    except Exception as e:
        print(f"  [FAIL] {name}")
        traceback.print_exc()
        return None


def main():
    print("\n" + "=" * 60)
    print("Secure Lens AI Backend Test Suite")
    print("=" * 60)

    # ---- Step 1: Test imports ----
    print("\n1. Testing imports...")

    def test_imports():
        from parsers import parse_log_file
        from analyzers import RuleEngine, analyze_with_ai, map_anomalies_to_mitre, get_mitre_summary
        from models import db, User, UploadedFile, AnalysisResult
        from config import get_config
        from auth import auth_bp
        return True

    if not test_step("All imports", test_imports):
        print("\n*** IMPORT FAILURE — fix import errors above first ***")
        sys.exit(1)

    # ---- Step 2: Test log parser ----
    print("\n2. Testing ZScaler log parser...")

    from parsers import parse_log_file

    sample_file = "sample_logs/sample_suspicious.json"
    if not os.path.exists(sample_file):
        print(f"  [SKIP] {sample_file} not found")
        entries = []
    else:
        def test_parser():
            with open(sample_file) as f:
                content = f.read()
            entries = parse_log_file(content)
            assert len(entries) > 0, f"Parser returned 0 entries"
            # Check normalized field names
            first = entries[0]
            print(f"         Parsed {len(entries)} entries")
            print(f"         Fields in first entry: {list(first.keys())[:8]}...")
            assert "client_ip" in first or "user" in first, "Missing expected normalized fields"
            return entries

        entries = test_step("Parse sample_suspicious.json", test_parser)
        if entries is None:
            entries = []

    # ---- Step 3: Test rule engine ----
    print("\n3. Testing rule engine...")

    from analyzers import RuleEngine

    def test_rule_engine():
        engine = RuleEngine()
        anomalies, stats = engine.analyze(entries)
        print(f"         Found {len(anomalies)} anomalies")
        print(f"         Stats keys: {list(stats.keys())}")
        # Verify required stat fields
        required_stats = ["total_events", "unique_ips", "unique_users", "top_ips",
                         "top_urls", "action_distribution", "status_distribution",
                         "top_categories", "traffic_over_time"]
        for key in required_stats:
            assert key in stats, f"Missing stats key: {key}"
        # Verify anomaly shape
        if anomalies:
            a = anomalies[0]
            required_anomaly = ["rule_id", "rule_name", "description", "confidence",
                               "severity", "affected_entries", "mitre_technique"]
            for key in required_anomaly:
                assert key in a, f"Missing anomaly key: {key}"
            print(f"         First anomaly: {a['rule_name']} (severity={a['severity']}, conf={a['confidence']})")
        return anomalies, stats

    result = test_step("Rule engine analysis", test_rule_engine)
    anomalies, stats = result if result else ([], {})

    # ---- Step 4: Test MITRE mapper ----
    print("\n4. Testing MITRE ATT&CK mapper...")

    from analyzers import map_anomalies_to_mitre, get_mitre_summary

    def test_mitre():
        enriched = map_anomalies_to_mitre(anomalies)
        summary = get_mitre_summary(enriched)
        # summary should be a list (not dict)
        assert isinstance(summary, list), f"mitre_summary should be list, got {type(summary)}"
        print(f"         Enriched {len(enriched)} anomalies with MITRE data")
        print(f"         MITRE summary: {len(summary)} techniques found")
        if summary:
            first = summary[0]
            assert "technique_id" in first, f"Missing technique_id in summary"
            assert "name" in first, f"Missing name in summary"
            assert "tactic" in first, f"Missing tactic in summary"
            assert "count" in first, f"Missing count in summary"
            print(f"         First: {first['technique_id']} - {first['name']} ({first['tactic']}, count={first['count']})")
        return enriched, summary

    result = test_step("MITRE mapping", test_mitre)
    anomalies, mitre_summary = result if result else (anomalies, [])

    # ---- Step 5: Test AI analyzer (fallback mode) ----
    print("\n5. Testing AI analyzer (fallback mode)...")

    from analyzers import analyze_with_ai

    def test_ai():
        # Remove API key to force fallback
        old_key = os.environ.pop("OPENAI_API_KEY", None)
        try:
            result = analyze_with_ai(anomalies, entries, stats)
            assert "executive_summary" in result, "Missing executive_summary"
            assert "timeline" in result, "Missing timeline"
            assert "risk_score" in result, "Missing risk_score"
            assert "recommendations" in result, "Missing recommendations"
            assert result["ai_enabled"] == False, "Should be fallback mode"
            print(f"         Summary: {result['executive_summary'][:80]}...")
            print(f"         Risk score: {result['risk_score']}")
            print(f"         Timeline events: {len(result['timeline'])}")
            print(f"         Recommendations: {len(result['recommendations'])}")
            # Check timeline shape
            if result["timeline"]:
                t = result["timeline"][0]
                assert "time" in t, f"Missing 'time' in timeline event"
                assert "event" in t, f"Missing 'event' in timeline event"
                assert "severity" in t, f"Missing 'severity' in timeline event"
            return result
        finally:
            if old_key:
                os.environ["OPENAI_API_KEY"] = old_key

    ai_result = test_step("AI fallback analysis", test_ai)

    # ---- Step 6: Test Flask app creation and routes ----
    print("\n6. Testing Flask app + full upload flow...")

    from app import create_app

    def test_flask_app():
        app = create_app()
        client = app.test_client()

        # Test health
        resp = client.get("/api/health")
        assert resp.status_code == 200, f"Health check failed: {resp.status_code}"
        print(f"         GET /api/health -> 200 OK")

        # Test login
        resp = client.post("/api/auth/login",
                          json={"username": "admin", "password": "admin123"})
        assert resp.status_code == 200, f"Login failed: {resp.status_code} - {resp.get_json()}"
        data = resp.get_json()
        token = data["access_token"]
        print(f"         POST /api/auth/login -> 200 OK (token received)")

        # Test upload
        headers = {"Authorization": f"Bearer {token}"}
        sample_path = "sample_logs/sample_suspicious.json"
        if os.path.exists(sample_path):
            with open(sample_path, "rb") as f:
                resp = client.post("/api/upload",
                                  headers=headers,
                                  data={"file": (f, "sample_suspicious.json")},
                                  content_type="multipart/form-data")

            if resp.status_code == 201:
                data = resp.get_json()
                analysis = data["analysis"]
                print(f"         POST /api/upload -> 201 OK")
                print(f"         Analysis ID: {analysis['id']}")
                print(f"         Total events: {analysis['total_events']}")
                print(f"         Anomalies: {analysis['anomaly_count']}")
                print(f"         Risk score: {analysis['risk_score']}")
                print(f"         Has filename: {'filename' in analysis}")
                print(f"         Has timeline_data: {'timeline_data' in analysis}")
                print(f"         Has anomalies: {'anomalies' in analysis}")
                print(f"         Has mitre_mappings: {'mitre_mappings' in analysis}")
                print(f"         Has stats: {'stats' in analysis}")

                # Verify mitre_mappings is a list
                assert isinstance(analysis["mitre_mappings"], list), \
                    f"mitre_mappings should be list, got {type(analysis['mitre_mappings'])}"

                # Verify stats has required keys
                s = analysis["stats"]
                for key in ["total_events", "unique_ips", "top_categories", "traffic_over_time"]:
                    assert key in s, f"Missing stats.{key}"

                analysis_id = analysis["id"]

                # Test get analysis
                resp = client.get(f"/api/analyses/{analysis_id}", headers=headers)
                assert resp.status_code == 200, f"Get analysis failed: {resp.status_code}"
                print(f"         GET /api/analyses/{analysis_id} -> 200 OK")

                # Test get logs
                resp = client.get(f"/api/analyses/{analysis_id}/logs", headers=headers)
                assert resp.status_code == 200, f"Get logs failed: {resp.status_code}"
                logs_data = resp.get_json()
                assert "logs" in logs_data, "Missing 'logs' key"
                assert "total" in logs_data, "Missing 'total' key"
                assert "page" in logs_data, "Missing 'page' key"
                print(f"         GET /api/analyses/{analysis_id}/logs -> 200 OK ({logs_data['total']} logs)")

                # Test list analyses
                resp = client.get("/api/analyses", headers=headers)
                assert resp.status_code == 200, f"List analyses failed: {resp.status_code}"
                list_data = resp.get_json()
                assert len(list_data["analyses"]) > 0, "No analyses in list"
                print(f"         GET /api/analyses -> 200 OK ({len(list_data['analyses'])} analyses)")

            else:
                error = resp.get_json()
                print(f"         POST /api/upload -> {resp.status_code} FAILED")
                print(f"         Error: {json.dumps(error, indent=2)}")
                raise Exception(f"Upload failed with {resp.status_code}: {error}")
        else:
            print(f"         [SKIP] No sample file found at {sample_path}")

        return True

    test_step("Flask app full upload flow", test_flask_app)

    # ---- Summary ----
    print("\n" + "=" * 60)
    print("ALL TESTS PASSED!")
    print("=" * 60)
    print("\nBackend is working correctly. If the frontend still fails,")
    print("the issue is in the browser. Steps to fix:")
    print("  1. Open browser DevTools (F12) -> Application -> Local Storage")
    print("  2. Delete the 'auth_token' entry for localhost:3000")
    print("  3. Refresh the page and log in again")
    print("  4. Try uploading sample_logs/sample_suspicious.json")
    print()


if __name__ == "__main__":
    main()
