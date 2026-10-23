#!/usr/bin/env python3
"""Rebuild the embedded dataset in index.html from the committed ns-3 results.

Reads results/exp2-attack-no-mitigation and results/exp3-attack-mitigated
(monitor-stats.csv, detections.csv, flowmon.xml) and rewrites the
`const DATA = {...};` line in index.html so the live dashboard always matches
the data in this repository. Run from the repo root:  python3 scripts/analysis/build_dashboard.py
"""
import csv, json, os, re, xml.etree.ElementTree as ET

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
HTML = os.path.join(ROOT, "index.html")
EXP = {"attack": "exp2-attack-no-mitigation", "mitigated": "exp3-attack-mitigated"}
SERVER, ATTACKER = "10.1.1.5", "10.1.1.4"
CLIENTS = {"10.1.1.1", "10.1.1.2", "10.1.1.3"}

def path(exp, name): return os.path.join(ROOT, "results", EXP[exp], name)

def load_ts(exp):
    rows = {}
    with open(path(exp, "monitor-stats.csv")) as f:
        for r in csv.DictReader(f):
            rows.setdefault(str(round(float(r["TimeSec"]))), {})[str(int(r["PortNo"]))] = round(float(r["PacketsPerSec"]))
    return rows

def load_det(exp):
    out = []
    with open(path(exp, "detections.csv")) as f:
        for r in csv.DictReader(f):
            out.append(dict(t=round(float(r["TimeSec"]), 3), port=int(r["PortNo"]), mac=r["SourceMac"],
                            pps=round(float(r["PacketsPerSec"])), thr=round(float(r["Threshold"])), event=r["Event"]))
    return out

def flow(exp):
    root = ET.parse(path(exp, "flowmon.xml")).getroot()
    cls = {fl.get("flowId"): fl.get("sourceAddress")
           for c in root.iter("Ipv4FlowClassifier") for fl in c.findall("Flow")}
    legit, atk = [0, 0], [0, 0]
    for fl in root.find("FlowStats").findall("Flow"):
        s = cls.get(fl.get("flowId")); tx, rx = int(fl.get("txPackets")), int(fl.get("rxPackets"))
        if s in CLIENTS: legit[0] += tx; legit[1] += rx
        elif s == ATTACKER: atk[0] += tx; atk[1] += rx
    return dict(legitDeliv=round(100*legit[1]/max(legit[0],1),1), atkDeliv=round(100*atk[1]/max(atk[0],1),1))

data = {"meta": {"server": SERVER, "clients": sorted(CLIENTS), "attacker": ATTACKER,
                 "threshold": 1000, "attackStart": 10, "simTime": 20,
                 "ports": {"1":"client","2":"client","3":"client","4":"attacker","5":"server"}}}
for exp in EXP:
    data[exp] = {"ts": load_ts(exp), "detections": load_det(exp), "flow": flow(exp)}

blob = "const DATA = " + json.dumps(data, separators=(",", ":")) + ";"
html = open(HTML).read()
html, n = re.subn(r"const DATA = \{.*?\};", lambda m: blob, html, count=1, flags=re.S)
assert n == 1, "DATA line not found in index.html"
open(HTML, "w").write(html)
print("index.html dataset rebuilt from results/")
print("  attack    legit delivery:", data["attack"]["flow"]["legitDeliv"], "%  (exp2)")
print("  mitigated legit delivery:", data["mitigated"]["flow"]["legitDeliv"], "%  (exp3)")
