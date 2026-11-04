from copy import deepcopy
from pathlib import Path

from kubernetes_ai_egress_guard.analyzer import analyze_documents, load_documents

SAMPLE = Path(__file__).parents[1] / "samples" / "compliant.yaml"


def docs():
    return load_documents([SAMPLE])


def finding_ids(data):
    return {item.rule_id for item in analyze_documents(data).findings}


def test_compliant_sample_passes():
    report = analyze_documents(docs())
    assert report.decision == "PASS"
    assert report.score == 100
    assert report.workloads_checked == 1


def test_missing_approved_domains_blocks():
    data = docs()
    del data[0]["spec"]["template"]["metadata"]["annotations"]
    assert "EG001" in finding_ids(data)


def test_default_service_account_reviews():
    data = docs()
    del data[0]["spec"]["template"]["spec"]["serviceAccountName"]
    assert "EG002" in finding_ids(data)


def test_missing_default_deny_blocks():
    data = [item for item in docs() if (item.get("metadata") or {}).get("name") != "default-deny-egress"]
    assert "EG003" in finding_ids(data)


def test_unbounded_destination_blocks():
    data = docs()
    data[2]["spec"]["egress"][0].pop("to")
    assert "EG004" in finding_ids(data)


def test_unbounded_port_blocks():
    data = docs()
    data[2]["spec"]["egress"][0].pop("ports")
    assert "EG005" in finding_ids(data)


def test_metadata_exposure_blocks():
    data = docs()
    data[2]["spec"]["egress"].append({"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}], "ports": [{"protocol": "TCP", "port": 443}]})
    assert "EG006" in finding_ids(data)


def test_missing_dns_rule_reviews():
    data = docs()
    data[2]["spec"]["egress"] = []
    assert "EG007" in finding_ids(data)


def test_wildcard_fqdn_reviews():
    data = docs()
    data[3]["spec"]["egress"][0]["toFQDNs"].append({"matchPattern": "*.example.com"})
    assert "EG008" in finding_ids(data)


def test_non_tls_model_egress_blocks():
    data = docs()
    data[3]["spec"]["egress"][0]["toPorts"][0]["ports"][0]["port"] = "80"
    assert "EG009" in finding_ids(data)


def test_missing_fqdn_policy_blocks():
    data = [item for item in docs() if item.get("kind") != "CiliumNetworkPolicy"]
    assert {"EG010", "EG011"}.issubset(finding_ids(data))


def test_undeclared_domain_reviews():
    data = deepcopy(docs())
    data[3]["spec"]["egress"][0]["toFQDNs"].append({"matchName": "unreviewed.example.com"})
    assert "EG012" in finding_ids(data)
