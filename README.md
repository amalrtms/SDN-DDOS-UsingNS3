# SDN-Based DDoS Detection and Mitigation Using NS-3

A final-year networking/security project. Simulates a Software-Defined
Network in NS-3 (using the OFSwitch13 OpenFlow 1.3 module), generates
legitimate client traffic plus a UDP flood from one or more attacker nodes,
detects the attacker using a plain packet-rate threshold at the SDN
controller (no machine learning, no AI), and mitigates it by pushing a
real OpenFlow DROP flow rule from the controller to the switch -- then
verifies legitimate traffic recovers.

Status: all 13 planned phases complete.

## Live demo

An interactive, browser-based replay of the real simulation output lives in
[`index.html`](index.html) and is published via GitHub Pages:

**https://amalrtms.github.io/SDN-DDOS-UsingNS3/**

It animates the network topology and plays back the measured per-source packet
rates, the controller's detection events, the two-stage DROP flow rules, the
source-entropy collapse, and the recovery of legitimate traffic. Toggle
**Controller mitigation** off to compare the detection-only run against the
mitigated run. Every number is read from the committed `results/` data; rebuild
it after new runs with `python3 scripts/analysis/build_dashboard.py`.

## Advanced controller (v2)

A second controller, `SdnControllerAdv` ([`src/controller/sdn-controller-adv.cc`](src/controller/sdn-controller-adv.cc)),
and the `ddos-advanced` experiment ([`simulations/ddos-advanced`](simulations/ddos-advanced))
extend the project in response to review feedback. The topology adds **one
shared switch port carrying both an attacker and an innocent client**, and the
number of clients and attackers is **randomised per run** (`--run`):

1. **Per-source detection** — polls OpenFlow `flow-stats` and aggregates by
   `eth_src`, so each host is measured even when several share one port (plain
   per-port stats cannot).
2. **Multi-signal + adaptive threshold** — flags a source only when its rate
   beats an adaptive baseline (`BaselineMultiplier × baseline`, floored at
   `MinThreshold`) **and** its average packet size is small. Source entropy and
   top-talker share are logged as extra indicators. (There is no international
   standard pps value for a DDoS — the threshold is deliberately baseline-relative.)
3. **Two-stage mitigation** — a coarse `in_port` DROP first, then a surgical
   `ip_src` DROP while the port block is lifted, so the innocent client sharing
   the attacker's port recovers (measured: **~83% delivery, same as a dedicated
   client**, vs ~30% with no mitigation).
4. **Penalties** — each offence is held down longer (5 s → 20 s → …); after
   `MaxStrikes` the source is permanently `BLACKLISTED`.

Run it with `./ns3 run "ddos-advanced --run=1"` (results in `results/adv-mitigated`
and `results/adv-attack`). Rate-limiting with OpenFlow **meters** instead of an
outright drop is left as future scope. The original Phase 1–13 controller and its
results are unchanged; the v1 dashboard is preserved as `index-v1.html`.

---

## 1. Project objective

Demonstrate, with a real NS-3 simulation (not a toy diagram), the full SDN
DDoS defense pipeline:

```
Normal traffic
      |
DDoS attack begins
      |
Controller monitors traffic (OpenFlow port statistics)
      |
Threshold-based detection (packets/sec > threshold?)
      |
Suspicious source identified (switch port + MAC)
      |
Controller installs a DROP flow-mod on the switch
      |
Attack traffic blocked at the switch
      |
Legitimate traffic recovers
```

...and to measure it: throughput, packet loss, delay, detection latency,
and how all of these change with attack intensity, detection threshold, and
attacker count.

## 2. Architecture

```
      Controller (our SdnController, C++, extends OFSwitch13Controller)
          |  OpenFlow 1.3 (control channel)
      SDN Switch (OFSwitch13Device, backed by the BOFUSS library)
       /    |    \                \
  Client1 Client2 Client3   Attacker(s)
       \    |    /                /
            \   /                /
           Server (victim, on a deliberately slower "bottleneck" access link)
```

- Every host (client, attacker, server) has its **own dedicated switch
  port** -- there is no shared Ethernet segment between hosts, only
  point-to-point CSMA links into the switch. This matters: it means a
  **per-port traffic rate is, in this topology, a per-source traffic
  rate**, which is what makes simple port-statistics polling enough for
  detection (see section 5).
- The server's own link to the switch is deliberately the slowest one
  (`10Mbps` by default vs `100Mbps` for everyone else) -- it models "the
  victim's access bandwidth," the resource a volumetric flood actually
  exhausts.
- One controller class, `SdnController` (`src/controller/sdn-controller.{h,cc}`),
  implements everything: L2 learning-switch forwarding, OpenFlow traffic
  monitoring, threshold detection, and DROP-rule mitigation. Mitigation can
  be switched off per run (`EnableMitigation` attribute) so the same class
  drives both the "attack without mitigation" and "attack with mitigation"
  experiments.

## 3. Requirements

| Component | Version used | Notes |
|---|---|---|
| OS | Ubuntu 24.04.4 LTS under WSL2 | |
| ns-3 | 3.40 | from `gitlab.com/nsnam/ns-3-dev`, tag `ns-3.40` |
| OFSwitch13 | 5.2.3 | from `github.com/ljerezchaves/ofswitch13` |
| GCC/G++ | 13.3.0 | |
| CMake | ≥3.10 (3.28.3 used) | ns-3's own build system |
| Python | 3.12 (either Windows or WSL) | only needed for `scripts/analysis/` (graphs) |
| matplotlib | any recent 3.x | the only non-stdlib Python dependency |

Full version-compatibility rationale and the exact apt package list are in
[`documentation/environment.md`](documentation/environment.md) -- including
two real bugs we hit and fixed (a glibc/strlcpy conflict on Ubuntu 24.04,
and an unrealistic CSMA channel delay that silently capped packet rates).
Read that file if you're setting this up on a different machine.

## 4. Installation

```bash
# 1. System packages (Ubuntu 24.04; adjust for your distro)
sudo apt update && sudo apt install -y g++ python3 cmake ninja-build git \
    make pkg-config libtool libboost-dev python3-pip python3-venv python3-dev

# 2. Clone ns-3.40
mkdir -p ~/sdn-ddos-project && cd ~/sdn-ddos-project
git clone --depth 1 --branch ns-3.40 https://gitlab.com/nsnam/ns-3-dev.git
cd ns-3-dev/contrib

# 3. Clone OFSwitch13 5.2.3 into contrib/
git clone https://github.com/ljerezchaves/ofswitch13.git
cd ofswitch13 && git checkout 5.2.3 && cd ../..

# 4. Apply the official ns-3.40 compatibility patch
patch -p1 < contrib/ofswitch13/utils/ofswitch13-3_40.patch

# 5. Configure + build (auto-downloads the BOFUSS library; needs internet)
./ns3 configure --enable-examples --enable-tests
./ns3 build -j4
```

**If you're on Ubuntu 24.04 (glibc ≥ 2.38)**, the build will fail on a
`strlcpy` redeclaration conflict inside BOFUSS -- this is a real,
reproducible incompatibility between BOFUSS's bundled `util.h` and glibc's
own (newer) `strlcpy`. The fix (two one-line header patches) is documented
in full, with the exact `sed` commands, in
[`documentation/environment.md`](documentation/environment.md#known-issue-strlcpy-conflict-on-ubuntu-2404-glibc-239).

Verify the install:
```bash
./ns3 run ofswitch13-first   # bundled example: two hosts, one switch, a ping
```

## 5. How to build and run this project

This project's own code (`simulations/`, `src/`) lives in this Windows-side
folder, separate from the ns-3 clone above (which lives natively in WSL for
build speed). `scripts/sync-build-run.sh` bridges the two: it copies our
code into ns-3's `scratch/` folder, builds just that target, and runs it.

```bash
cd scripts

# One simulation:
bash sync-build-run.sh ddos-mitigated
bash sync-build-run.sh ddos-mitigated -- --attackRate=30Mbps   # pass sim args after --

# The whole Phase 11 experiment matrix:
bash run-experiments.sh

# Everything -- build, run every experiment, generate graphs, print a summary:
bash run-all.sh
```

`run-all.sh` is **the one command** for this whole project (build -> run ->
generate results -> generate graphs -> inspect). It also sets up a Python
venv with matplotlib on first run if one doesn't exist yet, so it works
from a clean WSL install with nothing extra installed beyond the ns-3
toolchain above.

Graphs alone (after `results/` is populated):
```bash
cd scripts/analysis && python generate_graphs.py   # or venv/bin/python from WSL
```

## 6. How DDoS detection works

No machine learning, no statistics beyond a single comparison -- this was
a hard requirement, not a simplification we chose for convenience.

1. **Monitoring** (`SdnController::RequestPortStats` / `ProcessPortStatsReply`,
   in `src/controller/sdn-controller.cc`): every `MonitorInterval` seconds
   (default 1s), the controller sends a real OpenFlow **port-statistics
   request** (`stats-port` dpctl command → `OFPMP_PORT_STATS` multipart
   message) to the switch. The switch replies with real packet/byte
   counters it maintains per port. The controller computes
   `(current - previous) / interval` to get packets/sec and bytes/sec per
   port, and logs every sample to `results/<experiment>/monitor-stats.csv`.

   We deliberately do **not** use packet-in counts for this: once a flow is
   learned and cached in the switch's flow table, matching packets stop
   being sent to the controller at all (that is the entire point of an SDN
   flow table). An ongoing flood is invisible to packet-in counting after
   its first packet. Port statistics, maintained by the switch datapath
   itself, see it regardless.

2. **Source identification**: because every host sits on its own dedicated
   switch port, a port number *is* a source identity in this topology. The
   controller also keeps a MAC-learning table (same one used for L2
   forwarding) so it can log a human-readable MAC alongside the port number.

3. **Threshold comparison** (`SdnController::CheckThreshold`): every time a
   rate is computed,
   ```cpp
   bool isSuspicious = packetsPerSec > m_pktRateThreshold;
   ```
   That is the entire detection rule. `m_pktRateThreshold` is an `ns3::TypeId`
   attribute (`PacketRateThreshold`, default **1000 packets/sec**), settable
   per run without recompiling (see section 8). Every transition
   (clean→suspicious or the reverse) is logged with its simulation
   timestamp to `results/<experiment>/detections.csv`.

## 7. How mitigation works

(`SdnController::InstallMitigation` / `RemoveMitigation`, same file.)

When a port transitions to suspicious, the controller sends a real
OpenFlow flow-mod:
```
flow-mod cmd=add,table=0,prio=200 in_port=<the suspicious port>
```
No action/instruction clause at all -- OpenFlow 1.3 defines a flow entry
with an empty instruction set as a silent **drop**. Priority 200 is above
both our learned forwarding flows (priority 100) and the table-miss entry
(priority 0), so this rule is matched first and the source's traffic never
reaches the rest of the pipeline, and never reaches the bottleneck link to
the server.

If the port's rate later drops back under the threshold, the controller
removes the rule (`flow-mod cmd=del,table=0 in_port=<port>`), restoring
normal forwarding -- this is what lets legitimate traffic recover if a
previously-flagged source goes quiet, and is the mechanism behind the
"legitimate traffic recovers" step in the project's pipeline diagram.

Mitigation can be disabled per simulation (`EnableMitigation` attribute,
default `true`) without touching detection at all -- this is how
`simulations/ddos-attack` (Experiment 2: attack, no mitigation) and
`simulations/ddos-mitigated` (Experiment 3+: attack, with mitigation) share
one controller implementation instead of duplicating it.

**Verified result** (Experiment 2 vs. 3, see `graphs/01_before_after_mitigation.png`):
legitimate client packet loss goes from **46.9% (unmitigated) to 5.2%
(mitigated)** against the same attack. Server's own received-packet rate,
checked directly from its pcap, drops straight back to the exact
pre-attack baseline (~366 pkt/s) within one polling interval of mitigation
kicking in.

## 8. How to modify attack rate / detection threshold / other parameters

Everything important is an `ns3::CommandLine` argument on
`simulations/ddos-mitigated/ddos-mitigated.cc` (and, minus `--threshold`/
`--numAttackers`, on `simulations/ddos-attack/ddos-attack.cc`). No
recompiling needed -- these are runtime arguments, passed after `--`:

```bash
# Attack rate (per attacker):
bash sync-build-run.sh ddos-mitigated -- --attackRate=40Mbps

# Detection threshold (packets/sec):
bash sync-build-run.sh ddos-mitigated -- --threshold=2000

# Number of simultaneous attackers:
bash sync-build-run.sh ddos-mitigated -- --numAttackers=5

# Several at once, plus a custom results folder name:
bash sync-build-run.sh ddos-mitigated --out=my-test -- \
    --attackRate=10Mbps --threshold=500 --numClients=5
```

Full parameter list (all have sensible defaults -- run with `--help` via
`./ns3 run "ddos-mitigated --help"` inside WSL for the authoritative list):

| Flag | Default | Meaning |
|---|---|---|
| `--numClients` | 3 | Legitimate client count |
| `--perClientRate` | 500Kbps | Each client's UDP send rate |
| `--numAttackers` | 1 | Attacker count |
| `--attackRate` | 20Mbps | Each attacker's flood rate |
| `--attackPacketSize` | 64 | Attacker's UDP payload size (bytes) |
| `--attackStart` / `--attackStop` | 10s / simTime-1s | Attack window |
| `--serverLinkRate` | 10Mbps | The bottleneck link into the server |
| `--threshold` | 1000 | Detection threshold, packets/sec |
| `--monitorInterval` | 1.0 | Controller polling interval, seconds |
| `--simTime` | 20 | Total simulation duration, seconds |
| `--enablePcap` | true | Set `false` to skip pcap capture (used for the bulk sweeps) |

## 9. What each source file does

```
simulations/
  baseline/baseline.cc           Phase 5: smallest working SDN network
                                  (1 client, 1 server) -- connectivity check.
  normal-traffic/normal-traffic.cc
                                  Phase 6: multiple legit clients, no attack.
                                  = Experiment 1.
  ddos-attack/ddos-attack.cc     Phase 7: adds one attacker; mitigation
                                  explicitly disabled. = Experiment 2.
  ddos-mitigated/ddos-mitigated.cc
                                  Phase 10: detection + mitigation active;
                                  supports --numAttackers/--threshold/
                                  --enablePcap. Drives Experiments 3-6.

src/controller/
  sdn-controller.h / .cc         SdnController: L2 learning switch +
                                  OpenFlow port-stats monitoring + threshold
                                  detection + DROP-flow mitigation, all in
                                  one class (sections 6-7 above).

scripts/
  sync-build-run.sh              Copy one simulation + controller into the
                                  WSL ns-3 build, build it, run it, log it.
  run-experiments.sh             Run the full Phase 11 experiment matrix.
  run-all.sh                     Build + run everything + generate graphs +
                                  print a summary. The one command.
  analysis/common.py             Parse flowmon.xml/detections.csv into
                                  plain Python dicts; separate legitimate
                                  vs. attacker flows.
  analysis/generate_graphs.py    Phase 12: produce graphs/*.png and
                                  results/summary.csv from results/.

documentation/
  environment.md                 Running log: exact versions, exact build
                                  commands, every bug we hit and how we
                                  diagnosed and fixed it (not guessed).
```

## 10. Experiments and how to reproduce them

Run `bash run-experiments.sh` (or `run-all.sh` for the graphs too). Pass
one or more group names to run a subset, e.g. `bash run-experiments.sh exp4`.

| # | Group | Name(s) | What it varies |
|---|---|---|---|
| 1 | `exp1` | `exp1-normal` | Normal traffic only -- the baseline. |
| 2 | `exp2` | `exp2-attack-no-mitigation` | Attack, detection logs but doesn't block. |
| 3 | `exp3` | `exp3-attack-mitigated` | Attack, full detection + mitigation. |
| 4 | `exp4` | `exp4-intensity-{low,medium,high}` | Attack rate: 5 / 20 / 50 Mbps, mitigated. |
| 5 | `exp5` | `exp5-threshold-{200,1000,5000}` | Detection threshold (pkt/s), fixed 20Mbps attack, mitigated. |
| 6 | `exp6` | `exp6-attackers-{1,3}` | 1 vs. 3 simultaneous attackers, mitigated. |

Each run writes to `results/<name>/`:
- `flowmon.xml` -- real per-flow throughput/delay/loss (ns-3 FlowMonitor).
- `monitor-stats.csv` -- per-port packets/sec and bytes/sec over time.
- `detections.csv` -- every DETECTED/CLEARED transition, with timestamps.
- `switch-stats-*.log` -- OFSwitch13's own datapath performance counters.
- `host-*.pcap` -- per-port packet captures (skipped when `--enablePcap=false`,
  used for the bulk sweeps 4-6 to save time/disk).

All graphs in `graphs/` and the table in `results/summary.csv` are
generated directly from these files by `scripts/analysis/generate_graphs.py`
-- nothing in this project's results or graphs is hand-entered or
estimated.

### Results at a glance

| Experiment | Legit loss | Legit throughput | Detection delay |
|---|---|---|---|
| Normal | 0.0% | 1.42 Mbps | -- |
| Attack, no mitigation | 46.9% | 0.75 Mbps | 1.0s (logged only) |
| Attack, mitigated | **5.2%** | **1.34 Mbps** | 1.0s (blocked) |
| 3 simultaneous attackers, mitigated | 9.5% | 1.28 Mbps | 1.0-1.6s |

See `graphs/01_before_after_mitigation.png` for the headline comparison, and
`results/summary.csv` for the full table across all 11 experiment runs.

## 11. Known limitations / honest caveats

- The detection-threshold sweep (Experiment 5) shows flat results across
  200/1000/5000 pkt/s because the tested attack (~39,062 pkt/s) is far
  above all three -- a real property of that experiment's specific setup,
  not a bug. A threshold *between* the legitimate rate (~122 pkt/s) and a
  weaker attack would be a more sensitive test; the parameters make this
  easy to run (`--attackRate=1.5Mbps --threshold=300`, say).
- Mitigation blocks by **switch port**, not by IP/MAC identity -- correct
  and sufficient for this topology (one host per port), but would need
  extending (matching on `eth_src`/`ip_src` instead of `in_port`) for a
  topology where multiple hosts can appear behind one port.
- Detection latency is bounded below by `MonitorInterval` (default 1s) --
  an attack is never caught faster than one polling cycle. Lowering the
  interval trades CPU/control-channel overhead for faster detection.
