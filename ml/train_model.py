#!/usr/bin/env python3
"""
ml/train_model.py

Phase 10-11 of the roadmap. Trains three candidate models on the
behavioral feature matrix, evaluates each with precision/recall/F1/FPR
(not just accuracy — the dataset is class-balanced by construction here,
but real captured data won't be), and saves the best-performing model.

Usage:
    python ml/train_model.py --sessions data/processed/labeled_sessions.csv --reference data/loldrivers_reference.csv
"""
import argparse
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "detection"))

import joblib
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

from detection.pipeline import build_session_table
from ml.features import build_feature_matrix, build_labels

CANDIDATES = {
    "random_forest": RandomForestClassifier(n_estimators=200, max_depth=8, random_state=42),
    "logistic_regression": LogisticRegression(max_iter=1000),
    "gradient_boosting": GradientBoostingClassifier(random_state=42),
}


def false_positive_rate(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return fp / (fp + tn) if (fp + tn) else 0.0


def evaluate(model, X_test, y_test):
    y_pred = model.predict(X_test)
    return {
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 3),
        "recall": round(recall_score(y_test, y_pred, zero_division=0), 3),
        "f1": round(f1_score(y_test, y_pred, zero_division=0), 3),
        "false_positive_rate": round(false_positive_rate(y_test, y_pred), 3),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sessions", default="data/processed/labeled_sessions.csv")
    parser.add_argument("--reference", default="data/loldrivers_reference.csv")
    parser.add_argument("--out-model", default="ml/models/model.joblib")
    parser.add_argument("--out-metrics", default="ml/models/metrics.json")
    args = parser.parse_args()

    session_table = build_session_table(args.sessions, args.reference)
    X, session_ids = build_feature_matrix(session_table)
    y = build_labels(session_table)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    results = {}
    fitted_models = {}
    for name, model in CANDIDATES.items():
        model.fit(X_train, y_train)
        metrics = evaluate(model, X_test, y_test)
        cv_f1 = cross_val_score(
            model,
            X_train,
            y_train,
            cv=5,
            scoring="f1"
        ).mean()
        metrics["cv_f1_mean"] = round(cv_f1, 3)
        results[name] = metrics
        fitted_models[name] = model
        print(f"{name}: {metrics}")

    best_name = max(results, key=lambda n: results[n]["cv_f1_mean"])
    best_model = fitted_models[best_name]
    print(f"\nBest model by F1: {best_name}")

    os.makedirs(os.path.dirname(args.out_model), exist_ok=True)
    joblib.dump(best_model, args.out_model)
    with open(args.out_metrics, "w") as f:
        json.dump({"best_model": best_name, "results": results}, f, indent=2)

    print(f"Saved model to {args.out_model}")
    print(f"Saved metrics to {args.out_metrics}")


if __name__ == "__main__":
    main()
