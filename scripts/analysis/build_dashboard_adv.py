#!/usr/bin/env python3
"""Rebuild the embedded v2 (advanced-controller) dataset in index.html.

Reads results/adv-attack and results/adv-mitigated (monitor-stats.csv,
detections.csv, metrics.csv, flowmon.xml), produced by
`./ns3 run "ddos-advanced --run=1"`, and rewrites the `const DATA_ADV = {...};`
line in index.html so the "Advanced controller (v2)" live replay always
matches the data committed to this repository.

Source roles (IP, port) are not hand-entered: a source counts as an attacker
if it appears in detections.csv, the server is whichever destination every
flow in flowmon.xml targets, a client that shares a switch port with an
attacker is "innocent", and everyone else is a plain client. Run from the
repo root:  python3 scripts/analysis/build_dashboard_adv.py
"""
import csv, json, os, re, xml.etree.ElementTree as ET

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
HTML = os.path.join(ROOT, "index.html")
EXP = {"attack": "adv-attack", "mitigated": "adv-mitigated"}


def path(exp, name):
    return os.path.join(ROOT, "results", EXP[exp], name)


def server_ip(exp):
    """The destination every real (non-control-channel) flow targets."""
    root = ET.parse(path(exp, "flowmon.xml")).getroot()
    cls = [fl.get("destinationAddress") for c in root.iter("Ipv4FlowClassifier") for fl in c.findall("Flow")]
    counts = {}
    for d in cls:
        counts[d] = counts.get(d, 0) + 1
    return max(counts, key=counts.get)


def load_detections(exp):
    out = []
    with open(path(exp, "detections.csv")) as f:
        for r in csv.DictReader(f):
            out.append(dict(
                t=round(float(r["TimeSec"]), 3), mac=r["SrcMac"], ip=r["SrcIp"], port=int(r["Port"]),
                pps=round(float(r["PacketsPerSec"])), thr=round(float(r["Threshold"])),
                offense=int(r["Offense"]), event=r["Event"],
            ))
    return out


def load_metrics(exp):
    out = {}
    with open(path(exp, "metrics.csv")) as f:
        for r in csv.DictReader(f):
            t = round(float(r["TimeSec"]))
            out[t] = dict(
                entropy=round(float(r["SourceEntropy"]), 3), top=round(float(r["TopTalkerPct"]), 1),
                baseline=round(float(r["BaselineRate"])), threshold=round(float(r["Threshold"])),
            )
    return out


def load_sources(exp, sim_time):
    """Dense per-second pps/state for every source, forward-filled across
    gaps (the controller only logs a row when a source has active traffic
    or a state transition, not every second)."""
    raw = {}
    order = []
    with open(path(exp, "monitor-stats.csv")) as f:
        for r in csv.DictReader(f):
            mac = r["SrcMac"]
            if mac not in raw:
                raw[mac] = dict(ip=r["SrcIp"], port=int(r["Port"]), samples={})
                order.append(mac)
            t = round(float(r["TimeSec"]))
            raw[mac]["samples"][t] = (round(float(r["PacketsPerSec"])), r["State"])
            if r["SrcIp"] != "unknown":
                raw[mac]["ip"] = r["SrcIp"]

    dense = {}
    for mac, s in raw.items():
        last_pps, last_state = 0, "NORMAL"
        series, states = {}, {}
        for t in range(0, sim_time + 1):
            if t in s["samples"]:
                last_pps, last_state = s["samples"][t]
            series[str(t)] = last_pps
            states[str(t)] = last_state
        dense[mac] = dict(ip=s["ip"], port=s["port"], rate=series, state=states)
    return dense, order


def flow_delivery(exp, server):
    root = ET.parse(path(exp, "flowmon.xml")).getroot()
    cls = {}
    for c in root.iter("Ipv4FlowClassifier"):
        for fl in c.findall("Flow"):
            cls[fl.get("flowId")] = (fl.get("sourceAddress"), fl.get("destinationAddress"))
    per = {}
    for fl in root.find("FlowStats").findall("Flow"):
        s, d = cls.get(fl.get("flowId"), ("?", "?"))
        if d != server:
            continue
        tx, rx = int(fl.get("txPackets")), int(fl.get("rxPackets"))
        a = per.setdefault(s, [0, 0])
        a[0] += tx
        a[1] += rx
    return per


def classify(sources, detections, server):
    """role: client | attacker | innocent | server, from the data itself."""
    attacker_ips = {d["ip"] for d in detections}
    port_has_attacker = {s["port"] for s in sources.values() if s["ip"] in attacker_ips}
    roles = {}
    for mac, s in sources.items():
        if s["ip"] == server or s["ip"] == "unknown":
            # the server itself never appears as a flow source, so its monitor-stats
            # row never resolves a real SrcIp -- that's how it's told apart here too.
            role = "server"
        elif s["ip"] in attacker_ips:
            role = "attacker"
        elif s["port"] in port_has_attacker:
            role = "innocent"
        else:
            role = "client"
        shared = sum(1 for o in sources.values() if o["port"] == s["port"]) > 1
        roles[mac] = (role, shared)
    return roles


def build(sim_time):
    srv = {e: server_ip(e) for e in EXP}
    assert srv["attack"] == srv["mitigated"], "server IP differs between runs"
    server = srv["mitigated"]

    data = {"meta": {"simTime": sim_time, "server": server}}
    for exp in EXP:
        sources, order = load_sources(exp, sim_time)
        detections = load_detections(exp)
        roles = classify(sources, detections, server)
        delivery = flow_delivery(exp, server)

        src_list = []
        for mac in order:
            s = sources[mac]
            role, shared = roles[mac]
            ip = server if role == "server" else s["ip"]
            tx, rx = delivery.get(ip, [0, 0])
            src_list.append(dict(
                mac=mac, ip=ip, port=s["port"], role=role, shared=shared,
                rate=s["rate"], state=s["state"],
                deliv=round(100 * rx / tx, 1) if tx else None,
            ))
        order_key = {"client": 0, "innocent": 1, "attacker": 2, "server": 3}
        src_list.sort(key=lambda d: (order_key[d["role"]], d["port"], d["mac"]))

        def agg(role_set):
            tx = sum(delivery.get(s["ip"], [0, 0])[0] for s in src_list if s["role"] in role_set)
            rx = sum(delivery.get(s["ip"], [0, 0])[1] for s in src_list if s["role"] in role_set)
            return round(100 * rx / tx, 1) if tx else 0.0

        data[exp] = dict(
            sources=src_list,
            detections=load_detections(exp),
            metrics=load_metrics(exp),
            flow=dict(clientDeliv=agg({"client"}), innocentDeliv=agg({"innocent"}), attackerDeliv=agg({"attacker"})),
        )
    return data


def main():
    # Both adv-* runs share the same 44s sim; read it from whichever has more rows.
    with open(path("mitigated", "metrics.csv")) as f:
        sim_time = max(round(float(r["TimeSec"])) for r in csv.DictReader(f))

    data = build(sim_time)
    blob = "const DATA_ADV = " + json.dumps(data, separators=(",", ":")) + ";"
    html = open(HTML).read()
    html, n = re.subn(r"const DATA_ADV = \{.*?\};", lambda m: blob, html, count=1, flags=re.S)
    assert n == 1, "DATA_ADV line not found in index.html"
    open(HTML, "w").write(html)
    print("index.html v2 dataset rebuilt from results/adv-*  (", len(blob), "bytes )")
    for exp in EXP:
        f = data[exp]["flow"]
        print(f"  {exp:<10} clients {f['clientDeliv']}%  innocent {f['innocentDeliv']}%  attackers {f['attackerDeliv']}%")


if __name__ == "__main__":
    main()
