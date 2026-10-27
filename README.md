# Agentic AI-Based Phishing URL Detection and Analysis System

An explainable, offline phishing URL triage prototype for the DSATM mini project. It combines a supervised Naive Bayes model using URL path/query patterns with a heuristic auditor and a local coordinator that compares their signals. Hostname brand text is excluded from ML features to reduce false positives on legitimate brand domains.

## Run

Requires Python 3.10 or later; inference uses only the Python standard library. The included trained model is `phishing_url_model.json.gz`.

```powershell
python detector.py "http://example.test/login/verify?account=1"
python detector.py "example.test" --json
python interactive.py
```

The agentic workflow validates the URL, runs the trained local URL model and the explainable heuristic auditor, then combines their evidence. With no strong rule flags, it lowers the model's weight to limit unsupported positive verdicts; when rules flag concerns, it gives the model greater weight while preserving the rule score. If the model and rules disagree, it flags the disagreement for cautious review. The model is supervised machine learning, not a generative AI or LLM. The program never opens or fetches a submitted URL. Its estimate is not proof that a site is safe or phishing.

## Reproducible training

The included model was trained using URL strings and labels from UCI's PhiUSIIL dataset. The dataset is distributed under CC BY 4.0; attribution: A. Prasad and S. Chandra, UCI Machine Learning Repository (2024), DOI: 10.1016/j.cose.2023.103545. To retrain, download the CSV from the [UCI dataset page](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+website+dataset), then run:

```powershell
python train_model.py path\to\data.csv
```

Training is grouped by dataset domain into an 80/20 split with seed 42. It writes `phishing_url_model.json.gz` and `evaluation.json`. Metrics describe that held-out dataset split and do not guarantee real-world performance.

To rebuild the PDF report, run `python build_report.py` followed by `python finalize_report.py`.

Do not use real credentials or visit suspicious links. Any SET demonstration must be performed only in an isolated, explicitly authorized lab.

## Team

| USN | Name |
|---|---|
| 1DT23CY016 | DAKSH |
| 1DT23CY009 | APURUPA |
| 1DT23CY010 | ASHA |
| 1DT23CY035 | PURAB |

See `Mini_Project_Report.pdf` for the full report.
