"""Explainable, offline heuristic URL risk analyzer for the mini project."""
from __future__ import annotations

import argparse
import ipaddress
import json
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit


SUSPICIOUS_TERMS = {
    "login": 12, "verify": 14, "account": 8, "update": 8,
    "secure": 5, "password": 15, "payment": 10, "wallet": 10,
    "signin": 12, "banking": 12, "support": 5, "confirm": 8,
}


@dataclass
class Finding:
    feature: str
    points: int
    explanation: str


@dataclass
class Analysis:
    url: str
    verdict: str
    risk_score: int
    findings: list[Finding]
    limitations: list[str]
    model_phishing_probability: float | None = None
    agent_steps: list[str] | None = None


def analyze_url(raw_url: str) -> Analysis:
    value = raw_url.strip()
    candidate = value if "://" in value else "https://" + value
    try:
        parts = urlsplit(candidate)
        host = (parts.hostname or "").lower().rstrip(".")
        _ = parts.port  # Force invalid port parsing to raise ValueError.
    except ValueError as exc:
        return Analysis(value, "Suspicious", 50,
                        [Finding("URL syntax", 50, f"The URL could not be parsed safely: {exc}.")],
                        ["This prototype is a triage aid, not a definitive classifier."])
    if not host:
        return Analysis(value, "Suspicious", 50,
                        [Finding("URL syntax", 50, "No valid host name was found.")],
                        ["This prototype is a triage aid, not a definitive classifier."])

    score = 0
    findings: list[Finding] = []

    def add(feature: str, points: int, explanation: str) -> None:
        nonlocal score
        score += points
        findings.append(Finding(feature, points, explanation))

    if len(value) > 75:
        add("URL length", 10, f"The URL is long ({len(value)} characters).")
    if len(value) > 120:
        add("URL length", 8, "The URL is unusually long and may hide its destination.")
    lowered = value.lower()
    terms = [term for term in SUSPICIOUS_TERMS if term in lowered]
    if terms:
        add("Sensitive terms", min(25, sum(SUSPICIOUS_TERMS[t] for t in terms)),
            "Contains terms often used in credential or payment lures: " + ", ".join(terms) + ".")
    if "@" in parts.netloc:
        add("User information", 18, "An @ symbol in the authority can obscure the actual destination host.")
    try:
        ipaddress.ip_address(host)
        add("IP address host", 18, "The URL uses a raw IP address instead of a recognizable domain.")
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) >= 5:
        add("Subdomain depth", 10, f"The host has many subdomain labels ({len(labels)}).")
    if "xn--" in host:
        add("Internationalized domain", 15, "The host contains punycode, which can be used in look-alike domains.")
    if host.count("-") >= 3:
        add("Hyphenated host", 8, "The host contains several hyphens, which can occur in deceptive look-alike names.")
    if parts.scheme.lower() != "https":
        add("Transport", 8, "The URL does not use HTTPS; this is a weak signal and not proof of phishing.")
    if parts.query.count("=") >= 6:
        add("Query complexity", 5, "The URL has many query parameters.")
    score = min(100, score)
    verdict = "Likely phishing" if score >= 50 else "Suspicious" if score >= 25 else "Likely legitimate"
    if not findings:
        findings.append(Finding("No heuristic flags", 0, "No configured URL heuristic was triggered."))
    return Analysis(value, verdict, score, findings, [
        "Heuristics can produce false positives and false negatives.",
        "The analyzer does not fetch pages, resolve reputation, or verify site ownership.",
        "A low score does not establish that a URL is safe; check the domain independently.",
    ])


def analyze_agentic(raw_url: str) -> Analysis:
    """Coordinate syntax, trained ML, and explainable rule-audit tools locally."""
    result = analyze_url(raw_url)
    if any(f.feature == "URL syntax" for f in result.findings):
        result.agent_steps = ["Input validation stopped the workflow because the URL could not be parsed."]
        return result
    steps = ["Input validator parsed the URL without opening it."]
    try:
        from ml_classifier import MODEL_PATH, load_model, predict_phishing_probability
        if not MODEL_PATH.exists():
            result.agent_steps = steps + ["ML model is not installed; using the explainable heuristic baseline."]
            return result
        model = load_model()
        probability = predict_phishing_probability(result.url, model)
    except Exception as exc:
        result.agent_steps = steps + [f"ML model unavailable ({type(exc).__name__}); using the explainable heuristic baseline."]
        return result

    steps.append("URL n-gram classifier estimated phishing probability locally.")
    steps.append("Heuristic auditor checked URL structure and produced human-readable signals.")
    # Keep the model conservative when the rule auditor has no corroborating
    # signals. Strong model-only scores can otherwise create false positives.
    if result.risk_score < 25:
        combined = round(0.40 * probability * 100 + 0.60 * result.risk_score)
        steps.append("No strong rule flags; reduced model weight to limit uncorroborated false positives.")
    else:
        combined = max(result.risk_score, round(0.70 * probability * 100 + 0.30 * result.risk_score))
        steps.append("Rule auditor found warning signals; combined them with the trained model score.")
    model_says_phishing = probability >= 0.5
    rules_say_phishing = result.risk_score >= 25
    if model_says_phishing != rules_say_phishing:
        steps.append("Disagreement branch activated; both signals are shown for review.")
        result.findings.append(Finding("Model/rule disagreement", 0,
            "The trained model and heuristic auditor gave different sides of the threshold; treat this result cautiously."))
    else:
        steps.append("Agreement branch combined model and rule evidence.")
    result.model_phishing_probability = round(probability, 4)
    result.risk_score = min(100, combined)
    if result.risk_score >= 50 and probability >= 0.5 or combined >= 60:
        result.verdict = "Likely phishing"
    elif result.risk_score >= 25 or combined >= 30:
        result.verdict = "Suspicious"
    else:
        result.verdict = "Likely legitimate"
    result.agent_steps = steps
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline explainable phishing URL triage")
    parser.add_argument("url", help="URL to analyze (the page will not be opened)")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    args = parser.parse_args()
    result = analyze_agentic(args.url)
    payload = asdict(result)
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"Verdict: {result.verdict} | Risk score: {result.risk_score}/100")
        if result.model_phishing_probability is not None:
            print(f"Trained model phishing estimate: {result.model_phishing_probability:.1%}")
        for finding in result.findings:
            print(f"- [{finding.points:+}] {finding.feature}: {finding.explanation}")
        if result.agent_steps:
            print("\nAgent workflow:")
            for step in result.agent_steps:
                print(f"- {step}")
        print("\nLimitations:")
        for item in result.limitations:
            print(f"- {item}")


if __name__ == "__main__":
    main()
