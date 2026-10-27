"""Train/evaluate the local URL classifier using the UCI PhiUSIIL CSV.

Download the UCI CSV separately and pass its path. No submitted URL is fetched.
Dataset labels: 0 phishing, 1 legitimate. We map phishing to the positive class.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path

from ml_classifier import url_features

MAX_FEATURES = 18000
SEED = 42


def read_rows(path: Path) -> list[tuple[str, int, str]]:
    # Deduplicate exact URL strings. Group the split by dataset Domain so one
    # host cannot occur in both train and test sets.
    rows: dict[str, tuple[int, str]] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        required = {"URL", "Domain", "label"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError("CSV must contain URL, Domain, and label columns")
        for row in reader:
            url = (row.get("URL") or "").strip()
            domain = (row.get("Domain") or "").strip().lower()
            raw_label = (row.get("label") or "").strip()
            if not url or not domain or raw_label not in {"0", "1"}:
                continue
            y = 1 if raw_label == "0" else 0
            # If a repeated URL has contradictory labels, exclude it.
            if url in rows and rows[url][0] != y:
                rows[url] = (-1, domain)
            else:
                rows.setdefault(url, (y, domain))
    return [(u, y, d) for u, (y, d) in rows.items() if y in {0, 1}]


def group_split(rows: list[tuple[str, int, str]]) -> tuple[list, list]:
    by_domain: dict[str, list] = defaultdict(list)
    for row in rows:
        by_domain[row[2]].append(row)
    # Stratify domain groups by their majority label, while ensuring that all
    # rows for a domain stay on the same side of the split.
    class_domains: dict[int, list[str]] = defaultdict(list)
    for domain, items in by_domain.items():
        majority = int(sum(y for _, y, _ in items) * 2 >= len(items))
        class_domains[majority].append(domain)
    rng = random.Random(SEED)
    test_domains: set[str] = set()
    for domains in class_domains.values():
        rng.shuffle(domains)
        test_domains.update(domains[:max(1, round(len(domains)*0.2))])
    train = [r for r in rows if r[2] not in test_domains]
    test = [r for r in rows if r[2] in test_domains]
    return train, test


def fit(train: list[tuple[str, int, str]]) -> dict:
    docs_by_class = Counter(y for _, y, _ in train)
    df_by_class = {0: Counter(), 1: Counter()}
    total_df: Counter = Counter()
    for url, y, _ in train:
        feats = url_features(url)
        total_df.update(feats)
        df_by_class[y].update(feats)
    vocab = [f for f, _ in total_df.most_common(MAX_FEATURES)]
    vocab_set = set(vocab)
    alpha = 1.0
    totals = {c: sum(df_by_class[c][f] for f in vocab_set) for c in (0, 1)}
    weights = {}
    for feature in vocab:
        # Multinomial Naive Bayes over binary URL-feature presence.
        p_phish = (df_by_class[1][feature] + alpha) / (totals[1] + alpha*len(vocab))
        p_legit = (df_by_class[0][feature] + alpha) / (totals[0] + alpha*len(vocab))
        weights[feature] = round(math.log(p_phish / p_legit), 8)
    prior = math.log((docs_by_class[1] + alpha) / (docs_by_class[0] + alpha))
    return {"format":"url-mnb-v1", "seed":SEED, "max_features":MAX_FEATURES,
            "train_documents":len(train), "class_documents":{"legitimate":docs_by_class[0],"phishing":docs_by_class[1]},
            "log_prior_odds":round(prior,8), "log_feature_odds":weights,
            "feature_count":len(vocab_set), "threshold":0.5}


def metrics(test: list[tuple[str, int, str]], model: dict) -> dict:
    from ml_classifier import predict_phishing_probability
    tp=tn=fp=fn=0
    for url, actual, _ in test:
        predicted = int(predict_phishing_probability(url, model) >= 0.5)
        if actual and predicted: tp+=1
        elif actual and not predicted: fn+=1
        elif predicted: fp+=1
        else: tn+=1
    precision=tp/(tp+fp) if tp+fp else 0.0
    recall=tp/(tp+fn) if tp+fn else 0.0
    return {"split":"domain-grouped 80/20, seed 42", "test_documents":len(test),
            "threshold":0.5,"positive_class":"phishing",
            "confusion_matrix":{"true_phishing":tp,"missed_phishing":fn,"false_alarm":fp,"true_legitimate":tn},
            "accuracy":(tp+tn)/len(test) if test else 0.0,"precision":precision,"recall":recall,
            "f1":2*precision*recall/(precision+recall) if precision+recall else 0.0,
            "warning":"Single dataset split; results are dataset-specific and are not a guarantee of real-world performance."}


def main() -> None:
    parser=argparse.ArgumentParser()
    parser.add_argument("csv",type=Path,help="Path to UCI PhiUSIIL data.csv")
    parser.add_argument("--output",type=Path,default=Path(__file__).with_name("phishing_url_model.json.gz"))
    args=parser.parse_args()
    rows=read_rows(args.csv)
    if len(rows)<100: raise SystemExit("Not enough labeled URL rows found")
    train,test=group_split(rows)
    model=fit(train)
    report=metrics(test,model)
    with gzip.open(args.output,"wt",encoding="utf-8") as f: json.dump(model,f,separators=(",",":"))
    metrics_path=Path(__file__).with_name("evaluation.json")
    metrics_path.write_text(json.dumps(report,indent=2),encoding="utf-8")
    print(json.dumps({"rows":len(rows),"train":len(train),"test":len(test),"features":model["feature_count"],"evaluation":report},indent=2))


if __name__=="__main__": main()
