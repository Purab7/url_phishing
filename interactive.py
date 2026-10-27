"""Interactive local prompt for the phishing URL triage prototype."""
from detector import analyze_agentic


def main() -> None:
    print("Phishing URL Analyzer - interactive local mode")
    print("Paste a URL to analyze, or type quit to exit. The URL is never opened.")
    while True:
        try:
            raw = input("URL> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if raw.lower() in {"quit", "exit"}:
            break
        if not raw:
            continue
        result = analyze_agentic(raw)
        print(f"Verdict: {result.verdict} | Risk score: {result.risk_score}/100")
        if result.model_phishing_probability is not None:
            print(f"Trained model phishing estimate: {result.model_phishing_probability:.1%}")
        for finding in result.findings:
            print(f"- [{finding.points:+}] {finding.feature}: {finding.explanation}")
        if result.agent_steps:
            print("Agent workflow:")
            for step in result.agent_steps:
                print(f"- {step}")
        print("Reminder: model and rules are triage aids, not proof; the URL was not opened.\n")


if __name__ == "__main__":
    main()
