"""Tiny local multinomial Naive Bayes URL classifier (standard library only)."""
from __future__ import annotations

import gzip
import ipaddress
import json
import math
import re
from pathlib import Path
from urllib.parse import urlsplit

MODEL_PATH = Path(__file__).with_name("phishing_url_model.json.gz")
TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def url_features(url: str) -> set[str]:
    raw = url.strip()[:2048]
    candidate = raw if "://" in raw else "https://" + raw
    try:
        parts = urlsplit(candidate)
        host = (parts.hostname or "").lower().rstrip(".")
        scheme = parts.scheme.lower()
        path_query = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
    except ValueError:
        host, scheme, path_query = "", "invalid", raw
    # Avoid learning brand/domain-name associations from host text. They often
    # create false positives for legitimate domains unseen in training.
    text = path_query.lower()[:2048]
    features: set[str] = {f"scheme:{scheme}"}
    labels = [part for part in host.split(".") if part]
    # Encode only affirmative host anomalies. Generic host shapes such as a
    # two-label .com domain are common among both legitimate and phishing URLs.
    if "xn--" in host:
        features.add("host_punycode:yes")
    if host.count("-") >= 3:
        features.add("host_many_hyphens:yes")
    if len(labels) >= 5:
        features.add("host_deep_subdomain:yes")
    try:
        ipaddress.ip_address(host)
        features.add("host_ip:yes")
    except ValueError:
        pass
    # Character n-grams and tokens come from the path/query, not the brand name.
    for n in (3, 4, 5):
        features.update(f"c{n}:{text[i:i+n]}" for i in range(max(0, len(text)-n+1)))
    # Whole tokens complement character patterns with meaningful path/query parts.
    features.update("w:" + word for word in TOKEN_SPLIT.split(text) if len(word) > 1)
    return features


def load_model(path: Path = MODEL_PATH) -> dict:
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        model = json.load(stream)
    if model.get("format") != "url-mnb-v1":
        raise ValueError("Unsupported or invalid phishing model format")
    return model


def predict_phishing_probability(url: str, model: dict | None = None) -> float:
    model = model or load_model()
    score = float(model["log_prior_odds"])
    weights = model["log_feature_odds"]
    for feature in url_features(url):
        score += weights.get(feature, 0.0)
    score = max(-40.0, min(40.0, score))
    return 1.0 / (1.0 + math.exp(-score))
