"""
OpenAI-powered analysis for complex pattern detection.
Uses hybrid approach: rule-based detection + AI enhancement.
"""

import os
import json
from typing import List, Dict, Any, Tuple
import random


def analyze_with_ai(
    rule_results: List[Dict[str, Any]],
    log_entries: List[Dict[str, Any]],
    stats: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Perform AI-powered analysis using OpenAI.

    Uses hybrid approach: takes rule engine results + log sample and enriches
    with AI insights. Falls back gracefully if API key is not available.

    Args:
        rule_results: List of anomalies from rule engine
        log_entries: Full list of parsed log entries
        stats: Statistics computed from rule engine

    Returns:
        Dictionary with:
        - executive_summary: str
        - timeline: List of significant events
        - additional_findings: str
        - risk_score: 0-100 integer
        - risk_assessment: str
        - recommendations: List[str]
        - ai_enabled: bool
    """
    api_key = os.environ.get("OPENAI_API_KEY")

    if not api_key:
        print("[AI_ANALYZER] No OpenAI API key found, using fallback analysis")
        return _fallback_analysis(rule_results, log_entries, stats)

    try:
        print("[AI_ANALYZER] Performing OpenAI analysis")
        return _openai_analysis(api_key, rule_results, log_entries, stats)
    except Exception as e:
        print(f"[AI_ANALYZER] OpenAI analysis failed: {str(e)}, using fallback")
        return _fallback_analysis(rule_results, log_entries, stats)


def _openai_analysis(
    api_key: str,
    rule_results: List[Dict[str, Any]],
    log_entries: List[Dict[str, Any]],
    stats: Dict[str, Any],
) -> Dict[str, Any]:
    """Perform analysis using OpenAI API."""
    from openai import OpenAI

    client = OpenAI(api_key=api_key)

    # Sample log entries to avoid token overload (max 20 for demo)
    sample_size = min(20, len(log_entries))
    log_sample = random.sample(log_entries, sample_size) if log_entries else []

    # Build prompt
    prompt = _build_ai_prompt(rule_results, log_sample, stats)

    # Call OpenAI with structured output
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            temperature=0.3,  # More deterministic
            max_tokens=1500,
        )

        response_text = response.choices[0].message.content

        # Try to parse as JSON if the model returns it
        try:
            result = json.loads(response_text)
        except json.JSONDecodeError:
            # Fallback if not valid JSON
            result = _parse_text_response(response_text)

        result["ai_enabled"] = True
        return result

    except Exception as e:
        print(f"[AI_ANALYZER] OpenAI API error: {str(e)}")
        raise


def _fallback_analysis(
    rule_results: List[Dict[str, Any]],
    log_entries: List[Dict[str, Any]],
    stats: Dict[str, Any],
) -> Dict[str, Any]:
    """Fallback analysis without OpenAI (rule-based only)."""
    anomaly_count = len(rule_results)
    total_events = stats.get("total_events", 0)

    # Calculate risk score based on rules
    confidence_scores = [r.get("confidence", 0.5) for r in rule_results]
    avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0

    # Risk score: 0-100 based on anomaly count and severity
    severity_weights = {
        "critical": 25,
        "high": 15,
        "medium": 8,
        "low": 2,
    }
    risk_score = 0
    for rule in rule_results:
        severity = rule.get("severity", "low")
        risk_score += severity_weights.get(severity, 5)
    risk_score = min(100, int(risk_score))

    # Build summary
    summary = f"Analyzed {total_events} log entries and detected {anomaly_count} potential security anomalies. "
    if anomaly_count == 0:
        summary += "No significant threats detected."
    elif anomaly_count <= 5:
        summary += "Threats are localized and should be investigated."
    elif anomaly_count <= 20:
        summary += "Moderate anomaly activity detected requiring investigation."
    else:
        summary += "High volume of anomalies detected. Comprehensive investigation recommended."

    # Timeline of events
    timeline = []
    for i, rule in enumerate(rule_results[:5]):  # Top 5 rules
        timeline.append({
            "time": f"Event {i + 1}",
            "event": rule.get("rule_name", "Unknown"),
            "severity": rule.get("severity", "medium"),
            "description": rule.get("description", ""),
        })

    recommendations = _generate_recommendations(rule_results, stats)

    return {
        "executive_summary": summary,
        "timeline": timeline,
        "additional_findings": "Rule-based analysis completed without AI enhancement.",
        "risk_score": risk_score,
        "risk_assessment": _get_risk_assessment(risk_score),
        "recommendations": recommendations,
        "ai_enabled": False,
    }


def _build_ai_prompt(
    rule_results: List[Dict[str, Any]],
    log_sample: List[Dict[str, Any]],
    stats: Dict[str, Any],
) -> str:
    """Build the prompt for OpenAI analysis."""
    rules_text = json.dumps(rule_results, indent=2)
    logs_text = json.dumps(log_sample, indent=2)
    stats_text = json.dumps(stats, indent=2)

    return f"""You are a cybersecurity analyst reviewing web proxy logs. Analyze the following data and provide a structured assessment.

RULE-BASED ANOMALIES DETECTED:
{rules_text}

SAMPLE LOG ENTRIES (representative sample):
{logs_text}

STATISTICS:
{stats_text}

Provide your analysis in the following JSON format:
{{
    "executive_summary": "2-3 sentence summary of the overall security posture",
    "timeline": [
        {{"event": "event name", "severity": "critical/high/medium/low", "description": "what happened"}},
        ...
    ],
    "additional_findings": "Any additional security patterns or concerns not captured by the rules",
    "risk_score": 0-100,
    "risk_assessment": "brief description of the risk level",
    "recommendations": [
        "Specific action 1",
        "Specific action 2",
        ...
    ]
}}

Focus on:
1. Executive summary of overall security posture
2. Timeline of significant events
3. Risk assessment (0-100 score)
4. Actionable recommendations for SOC analysts
5. Any patterns the rules might have missed

Return ONLY valid JSON."""


def _parse_text_response(text: str) -> Dict[str, Any]:
    """Parse text response when model doesn't return JSON."""
    # Try to extract JSON from the text
    import re

    json_match = re.search(r"\{.*\}", text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass

    # Fallback to basic parsing
    return {
        "executive_summary": text[:200],
        "timeline": [],
        "additional_findings": text,
        "risk_score": 50,
        "risk_assessment": "Unable to fully assess",
        "recommendations": ["Review logs manually", "Consult security team"],
    }


def _generate_recommendations(
    rule_results: List[Dict[str, Any]],
    stats: Dict[str, Any],
) -> List[str]:
    """Generate recommendations based on detected rules."""
    recommendations = []

    # Check for specific threats and make recommendations
    rule_ids = {r.get("rule_id") for r in rule_results}

    if "MALICIOUS_CATEGORY" in rule_ids:
        recommendations.append("Immediately isolate affected systems and review malware detection alerts")
        recommendations.append("Block detected domains/IPs at perimeter firewall")

    if "DATA_EXFILTRATION" in rule_ids:
        recommendations.append("Investigate large uploads to external destinations")
        recommendations.append("Review user accounts for unauthorized access")

    if "DNS_TUNNELING" in rule_ids:
        recommendations.append("Monitor for DNS tunneling activity and block suspicious domains")

    if "REPEATED_FAILED_REQUESTS" in rule_ids:
        recommendations.append("Check for brute force attacks against web applications")
        recommendations.append("Review account lockout policies")

    if "HIGH_FREQ_IP" in rule_ids:
        recommendations.append("Analyze high-frequency source IPs for scanning or flooding activity")

    if "SUSPICIOUS_USER_AGENT" in rule_ids:
        recommendations.append("Identify and block known scanning and automation tools")

    # General recommendations
    if not recommendations:
        recommendations.append("Continue baseline monitoring and threat hunting")
    else:
        recommendations.append("Enable enhanced logging for affected users/IPs")
        recommendations.append("Review firewall and proxy configurations")

    return recommendations[:5]  # Top 5 recommendations


def _get_risk_assessment(risk_score: int) -> str:
    """Get risk assessment text based on score."""
    if risk_score >= 80:
        return "CRITICAL - Immediate action required"
    elif risk_score >= 60:
        return "HIGH - Urgent investigation needed"
    elif risk_score >= 40:
        return "MEDIUM - Monitor and investigate"
    elif risk_score >= 20:
        return "LOW - Keep under observation"
    else:
        return "MINIMAL - Normal activity patterns"
