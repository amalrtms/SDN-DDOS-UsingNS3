#!/usr/bin/env python3
"""Rebuild the live dashboard's embedded dataset from the advanced (v2) results.

Reads results/adv-mitigated and results/adv-attack (monitor-stats.csv,
detections.csv, metrics.csv, flowmon.xml) produced by simulations/ddos-advanced,
derives each source's role (client / attacker / innocent-on-shared-port / server)
straight from the data, and rewrites the `const DATA = {...};` line in index.html.

Run from the repo root:  python3 scripts/analysis/build_dashboard.py
"""
import csv, json, os, re, sys, xml.etree.ElementTree as ET

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
HTML = os.path.join(ROOT, "index.html")
EXP = {"mitigated": "adv-mitigated", "attack": "adv-attack"}
SIM = 45


def rp(exp, name):
    return os.path.join(ROOT, "results", EXP[exp], name)


def flow_delivery(exp):
    """Per-source packet delivery to the server, and the server IP, from flowmon."""
    root = ET.parse(rp(exp, "flowmon.xml")).getroot()
    cls = {}
    for c in root.iter("Ipv4FlowClassifier"):
        for fl in c.findall("Flow"):
            cls[fl.get("flowId")] = (fl.get("sourceAddress"), fl.get("destinationAddress"))
    dstcount = {}
    for fid, (s, d) in cls.items():
        dstcount[d] = dstcount.get(d, 0) + 1
    server_ip = max(dstcount, key=dstcount.get)
    per = {}
    for fl in root.find("FlowStats").findall("Flow"):
        s, d = cls.get(fl.get("flowId"), ("?", "?"))
        if d != server_ip:
            continue
        tx, rx = int(fl.get("txPackets")), int(fl.get("rxPackets"))
        per[s] = dict(tx=tx, rx=rx, deliv=round(100 * rx / max(tx, 1), 1))
    return server_ip, per


def load_sources(exp, detected_ips, server_ip):
    rows = {}
    with open(rp(exp, "monitor-stats.csv")) as f:
        for r in csv.DictReader(f):
            mac = r["SrcMac"]
            sec = round(float(r["TimeSec"]))
            s = rows.setdefault(mac, dict(ip=r["SrcIp"], port=int(r["Port"]),
                                          rate={}, state={}, maxpps=0.0))
            pps = round(float(r["PacketsPerSec"]))
            s["rate"][sec] = pps
            s["state"][sec] = r["State"]
            s["maxpps"] = max(s["maxpps"], pps)
            if r["SrcIp"] != "unknown":
                s["ip"] = r["SrcIp"]
            s["port"] = int(r["Port"])
    port_has_attacker = {s["port"] for s in rows.values() if s["ip"] in detected_ips}
    out = []
    for mac, s in rows.items():
        if s["ip"] in detected_ips:
            role = "attacker"
        elif s["ip"] == "unknown" and s["maxpps"] == 0:
            role = "server"
        else:
            role = "client"
        shared = False
        if role == "client" and s["port"] in port_has_attacker:
            role = "innocent"
            shared = True
        if role == "attacker":
            shared = any(o["port"] == s["port"] and o["ip"] not in detected_ips
                         and o["ip"] != "unknown" for o in rows.values())
        out.append(dict(mac=mac, ip=(server_ip if role == "server" else s["ip"]),
                        port=s["port"], role=role, shared=bool(shared),
                        rate=[s["rate"].get(t, 0) for t in range(1, SIM)],
                        state=[s["state"].get(t, "NORMAL") for t in range(1, SIM)]))
    order = {"client": 0, "innocent": 1, "attacker": 2, "server": 3}
    out.sort(key=lambda d: (order[d["role"]], d["port"]))
    return out


def load_metrics(exp):
    t, ent, top, thr = [], [], [], []
    with open(rp(exp, "metrics.csv")) as f:
        for r in csv.DictReader(f):
            t.append(round(float(r["TimeSec"]), 1))
            ent.append(round(float(r["SourceEntropy"]), 3))
            top.append(round(float(r["TopTalkerPct"]), 1))
            thr.append(round(float(r["Threshold"]), 0))
    return dict(t=t, entropy=ent, topPct=top, threshold=thr)


def load_events(exp):
    out = []
    with open(rp(exp, "detections.csv")) as f:
        for r in csv.DictReader(f):
            out.append(dict(t=round(float(r["TimeSec"]), 3), mac=r["SrcMac"], ip=r["SrcIp"],
                            port=int(r["Port"]), pps=round(float(r["PacketsPerSec"])),
                            off=int(r["Offense"]), event=r["Event"]))
    return out


def build_exp(exp):
    server_ip, per = flow_delivery(exp)
    detected = set()
    with open(rp(exp, "detections.csv")) as f:
        for r in csv.DictReader(f):
            if r["SrcIp"] != "unknown":
                detected.add(r["SrcIp"])
    sources = load_sources(exp, detected, server_ip)

    def agg(pred):
        tx = sum(per[s["ip"]]["tx"] for s in sources if pred(s) and s["ip"] in per)
        rx = sum(per[s["ip"]]["rx"] for s in sources if pred(s) and s["ip"] in per)
        return round(100 * rx / max(tx, 1), 1)

    flow = dict(
        legitDeliv=agg(lambda s: s["role"] in ("client", "innocent")),
        innocentDeliv=agg(lambda s: s["role"] == "innocent"),
        attackerDeliv=agg(lambda s: s["role"] == "attacker"),
        bySrc={s["ip"]: per.get(s["ip"], {}).get("deliv", 0) for s in sources},
    )
    return dict(sources=sources, metrics=load_metrics(exp), events=load_events(exp), flow=flow)


def main():
    server_ip, _ = flow_delivery("mitigated")
    data = {
        "meta": {"simTime": SIM, "attackStart": 10, "monitorInterval": 1,
                 "smallPacketBytes": 256, "serverIp": server_ip},
        "mitigated": build_exp("mitigated"),
        "attack": build_exp("attack"),
    }
    blob = "const DATA = " + json.dumps(data, separators=(",", ":")) + ";"
    if "--dump" in sys.argv:
        print(json.dumps(data, indent=1)[:3500])
        print("... total bytes:", len(blob))
        return
    html = open(HTML).read()
    html, n = re.subn(r"const DATA = \{.*?\};", lambda m: blob, html, count=1, flags=re.S)
    assert n == 1, "DATA line not found in index.html"
    open(HTML, "w").write(html)
    print("index.html rebuilt from adv results.  DATA size:", len(blob), "bytes")
    for e in ("mitigated", "attack"):
        f = data[e]["flow"]
        print(f"  {e:<10} legit {f['legitDeliv']}%  innocent {f['innocentDeliv']}%  attacker {f['attackerDeliv']}%")


if __name__ == "__main__":
    main()
