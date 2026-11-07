"""Measures the description scanner on bench/corpus.json.

    python bench/run.py            # print the table
    python bench/run.py --write    # also rewrite bench/results.json
    python bench/run.py --cisco    # also run Cisco's offline YARA analyzer, if installed

A tool definition goes through exactly the path a live `--deep` probe uses
(deep.normalize_tool, then deep.audit_descriptions). A rug-pull entry is
pinned in its first form and compared with its second (toolset.compare); a
shadowing entry is judged next to a second server that offers the `siblings`
(toolset.shadowing). "Flagged" means at least one finding of any severity;
"medium+" counts only findings that would normally move a grade.
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from mcp_gradecard import deep, toolset            # noqa: E402

RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def load():
    with open(os.path.join(HERE, "corpus.json"), encoding="utf-8") as f:
        return json.load(f)["entries"]


def findings_for(entry):
    """All findings the tool makes about one corpus entry."""
    tools = [deep.normalize_tool(entry["tool"])]
    server = entry.get("server")
    found = deep.audit_descriptions(tools, server)
    if "v2" in entry:
        now = deep.normalize_tool(entry["v2"])
        pinned = toolset.snapshot(tools, server)
        found += toolset.compare(pinned, toolset.snapshot([now], server), True)
    if entry.get("siblings"):
        mine = {"name": "tested", "client": "claude-code", "config": {"command": "a"},
                "tools": tools, "deep_read": True, "deep_server": server}
        other = {"name": "other", "client": "claude-code", "config": {"command": "b"},
                 "tools": [{"name": n, "description": "x"} for n in entry["siblings"]],
                 "deep_read": True}
        found += toolset.shadowing([mine, other]).get(id(mine), [])
    return found


def measure(entries):
    rows = []
    for e in entries:
        found = findings_for(e)
        worst = max((RANK.get(f["severity"], 0) for f in found), default=-1)
        rows.append({"id": e["id"], "label": e["label"], "class": e["class"],
                     "split": e.get("split", "dev"),
                     "flagged": bool(found), "medium_plus": worst >= 1,
                     "high_plus": worst >= 2,
                     "checks": sorted({f["check"] for f in found})})
    return rows


def rates(rows, key):
    tp = sum(r["label"] == "malicious" and r[key] for r in rows)
    fn = sum(r["label"] == "malicious" and not r[key] for r in rows)
    fp = sum(r["label"] == "benign" and r[key] for r in rows)
    tn = sum(r["label"] == "benign" and not r[key] for r in rows)
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "precision": round(prec, 3), "recall": round(rec, 3),
            "false_positive_rate": round(fpr, 3)}


def summary(rows):
    classes = {}
    for r in rows:
        if r["label"] == "malicious":
            c = classes.setdefault(r["class"], {"n": 0, "flagged": 0})
            c["n"] += 1
            c["flagged"] += r["flagged"]
    return {"malicious": sum(r["label"] == "malicious" for r in rows),
            "benign": sum(r["label"] == "benign" for r in rows),
            "any_finding": rates(rows, "flagged"),
            "medium_plus": rates(rows, "medium_plus"),
            "high_plus": rates(rows, "high_plus"),
            "recall_by_class": classes,
            "missed": [r["id"] for r in rows if r["label"] == "malicious" and not r["flagged"]],
            "false_positives": [r["id"] for r in rows if r["label"] == "benign" and r["flagged"]]}


def show(s):
    print("corpus: %d malicious, %d benign" % (s["malicious"], s["benign"]))
    for k, name in (("any_finding", "any finding"), ("medium_plus", "medium or higher"),
                    ("high_plus", "high or higher")):
        r = s[k]
        print("%-18s precision %.3f  recall %.3f  false-positive rate %.3f  (tp %d fn %d fp %d tn %d)"
              % (name, r["precision"], r["recall"], r["false_positive_rate"],
                 r["tp"], r["fn"], r["fp"], r["tn"]))
    print("recall by class (any finding):")
    for c, v in sorted(s["recall_by_class"].items()):
        print("  %-12s %2d/%2d" % (c, v["flagged"], v["n"]))
    print("missed:", ", ".join(s["missed"]) or "none")
    print("false positives:", ", ".join(s["false_positives"]) or "none")


def cisco(entries):
    """Cisco's YARA analyzer on the same tool definitions (offline)."""
    import asyncio
    from mcpscanner.core.analyzers.yara_analyzer import YaraAnalyzer
    an = YaraAnalyzer()
    flagged = {}
    for e in entries:
        t = e["tool"]
        text = json.dumps(t, ensure_ascii=False)
        try:
            res = asyncio.run(an.analyze(text, {"tool_name": t["name"], "content_type": "tool"}))
            flagged[e["id"]] = bool(res)
        except Exception as ex:                       # noqa: BLE001
            flagged[e["id"]] = False
            print("cisco error on", e["id"], type(ex).__name__, file=sys.stderr)
    return flagged


def split_summary(rows):
    return {name: summary([r for r in rows if r["split"] == name])
            for name in ("dev", "holdout", "r3", "r3b")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--cisco", action="store_true")
    a = ap.parse_args()
    entries = load()
    rows = measure(entries)
    s = summary(rows)
    s["splits"] = {k: {kk: v[kk] for kk in ("malicious", "benign", "any_finding", "medium_plus",
                                             "high_plus", "missed", "false_positives")}
                   for k, v in split_summary(rows).items()}
    show(s)
    for k, v in s["splits"].items():
        print("\n[%s split] %d malicious, %d benign" % (k, v["malicious"], v["benign"]))
        for key in ("any_finding", "medium_plus"):
            r = v[key]
            print("  %-12s precision %.3f recall %.3f false-positive rate %.3f"
                  % (key, r["precision"], r["recall"], r["false_positive_rate"]))
        print("  missed:", ", ".join(v["missed"]) or "none")
        print("  false positives:", ", ".join(v["false_positives"]) or "none")
    if a.cisco:
        e_split = {e["id"]: e.get("split", "dev") for e in entries}
        fl = cisco(entries)
        crow = [{"id": e["id"], "label": e["label"], "class": e["class"], "flagged": fl[e["id"]],
                 "medium_plus": fl[e["id"]], "high_plus": fl[e["id"]]} for e in entries]
        print("\nCisco YARA analyzer, same corpus:")
        show(summary(crow))
        # Cisco's analyzer reads one tool at a time: no pins, no other servers.
        text = {"rug-pull", "rug-pull-control", "shadowing"}
        print("\nText classes only (no rug-pull, no shadowing), all splits together:")
        for name, rs in (("mcp-gradecard", rows), ("Cisco YARA", crow)):
            r = rates([x for x in rs if x["class"] not in text], "flagged")
            print("  %-14s precision %.3f recall %.3f false-positive rate %.3f"
                  % (name, r["precision"], r["recall"], r["false_positive_rate"]))
        for split in ("holdout", "r3", "r3b"):
            print("%s only:" % split.capitalize())
            for name, rs in (("mcp-gradecard", rows), ("Cisco YARA", crow)):
                r = rates([x for x in rs if x["class"] not in text
                           and e_split[x["id"]] == split], "flagged")
                print("  %-14s precision %.3f recall %.3f false-positive rate %.3f"
                      % (name, r["precision"], r["recall"], r["false_positive_rate"]))
    if a.write:
        with open(os.path.join(HERE, "results.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(s, f, indent=1, sort_keys=True)
            f.write("\n")


if __name__ == "__main__":
    main()
