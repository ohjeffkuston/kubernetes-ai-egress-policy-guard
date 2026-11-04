"""Command line interface."""

from __future__ import annotations

import argparse
import json

from .analyzer import analyze_documents, load_documents


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Kubernetes AI workload egress policy before GitOps merge")
    parser.add_argument("paths", nargs="+", help="Kubernetes YAML file or directory")
    parser.add_argument("--output", choices=("text", "json"), default="text")
    args = parser.parse_args()
    report = analyze_documents(load_documents(args.paths))
    if args.output == "json":
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"Decision: {report.decision} | Score: {report.score} | Workloads: {report.workloads_checked}")
        for finding in report.findings:
            print(f"[{finding.severity}] {finding.rule_id} {finding.resource}: {finding.message}")
    return 0 if report.decision == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
