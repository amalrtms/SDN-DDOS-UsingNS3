// Project v2 experiment: the advanced controller (SdnControllerAdv) on a
// topology that has, in addition to the usual one-host-per-port links, ONE
// SHARED switch port carrying both an attacker and an innocent client. That
// shared segment is what makes per-IP isolation meaningful:
//
//   Client 1 ... Client N   Attacker 1 ... Attacker M        Server
//        \         |            |             /                 |
//         \        |            |            /                  |
//          +------------- SDN Switch --------+---- shared port -+
//                           |                         |
//                        Server link         Attacker_s  Client_s   <- same port
//
// Numbers of clients and dedicated attackers, AND the attack's start time, are
// all RANDOM per run (seeded by --run) unless pinned on the command line.
//
// Optionally (--numLowRateAttackers, off by default so the existing committed
// results/adv-* stay reproducible), a pool of LOW-rate attackers joins too --
// each individually sends below the per-source detection threshold, so no
// single one of them trips the per-source detector; only their combined
// weight against the learned AGGREGATE baseline does (see "distributed-attack
// 2nd signal" in sdn-controller-adv.h). This models a real botnet-style flood
// from many unremarkable devices, e.g. the 3.47 Tbps / ~10,000-source attack
// Microsoft reported against an Azure customer in Nov 2021.
//
// What the advanced controller does with this (see sdn-controller-adv.h):
//   per-source flow-stats detection -> multi-signal (rate AND small packets)
//   with an adaptive baseline threshold -> two-stage mitigation (coarse port
//   block, then surgical per-IP block that frees the innocent client sharing
//   the port) -> escalating hold-down penalties and a blacklist for repeat
//   offenders -> an aggregate-rate 2nd signal that catches a flood spread
//   across many individually-small devices.

#include "sdn-controller-adv.h"

#include <ns3/applications-module.h>
#include <ns3/core-module.h>
#include <ns3/csma-module.h>
#include <ns3/flow-monitor-module.h>
#include <ns3/internet-module.h>
#include <ns3/network-module.h>
#include <ns3/ofswitch13-module.h>
#include <ns3/traffic-control-module.h>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("DdosAdvanced");

int
main(int argc, char* argv[])
{
    uint32_t numClients = 0;   // 0 => random in [2,5]
    uint32_t numAttackers = 0; // 0 => random in [1,3] (dedicated-port attackers)
    uint32_t run = 1;          // RNG run number (varies the random counts/timing)
    double simTime = 45.0;     // long enough to show repeat-offence escalation -> blacklist

    std::string perClientRate = "500Kbps";
    uint32_t clientPacketSize = 512;
    std::string attackRate = "20Mbps";
    uint32_t attackPacketSize = 64;
    double attackStart = -1.0; // -1 => random (seeded by --run); see range below
    double attackStop = -1.0;

    // Distributed (multi-device) attack pool: OFF by default (0) so the
    // existing committed results/adv-attack and results/adv-mitigated stay
    // exactly reproducible. Pass --numLowRateAttackers to exercise the
    // aggregate-rate 2nd detection signal (see sdn-controller-adv.h).
    uint32_t numLowRateAttackers = 0;
    std::string lowRateAttackRate = "80Kbps"; // per-device; well under the per-source threshold

    std::string hostLinkRate = "100Mbps";
    std::string serverLinkRate = "10Mbps";

    double threshold = 500.0; // MinThreshold floor for the adaptive detector
    double monitorInterval = 1.0;
    bool mitigation = true;
    bool twoStage = true;
    bool enablePcap = false;

    // Distributed-attack 2nd signal (see sdn-controller-adv.h) -- tunable from
    // the command line so a --numLowRateAttackers run can be dialed in without
    // recompiling.
    double aggMultiplier = 3.0;
    double alertThresholdFactor = 0.3;

    CommandLine cmd;
    cmd.AddValue("numClients", "Legitimate clients on dedicated ports (0 = random 2-5)", numClients);
    cmd.AddValue("numAttackers", "Attackers on dedicated ports (0 = random 1-3)", numAttackers);
    cmd.AddValue("numLowRateAttackers",
                "Extra attackers flooding BELOW the per-source threshold each (0 = off; models "
                "a many-device botnet flood -- only the aggregate-rate 2nd signal catches it)",
                numLowRateAttackers);
    cmd.AddValue("lowRateAttackRate", "Each low-rate attacker's flood rate", lowRateAttackRate);
    cmd.AddValue("run", "RNG run number (varies the random host counts/timing)", run);
    cmd.AddValue("simTime", "Simulation duration (s)", simTime);
    cmd.AddValue("perClientRate", "UDP rate per legitimate client", perClientRate);
    cmd.AddValue("attackRate", "Each (dedicated/shared) attacker's flood rate", attackRate);
    cmd.AddValue("attackPacketSize", "Attacker flood packet size (bytes)", attackPacketSize);
    cmd.AddValue("attackStart", "Attack start time (s, -1 = random 9-14s, seeded by --run)",
                attackStart);
    cmd.AddValue("attackStop", "Attack stop time (s, -1 = near sim end)", attackStop);
    cmd.AddValue("serverLinkRate", "Server (bottleneck) link rate", serverLinkRate);
    cmd.AddValue("threshold", "MinThreshold floor (pps) for the adaptive detector", threshold);
    cmd.AddValue("monitorInterval", "Controller polling interval (s)", monitorInterval);
    cmd.AddValue("mitigation", "Enable mitigation (false = detection only)", mitigation);
    cmd.AddValue("twoStage", "Use the two-stage port->IP mitigation", twoStage);
    cmd.AddValue("aggMultiplier",
                "Distributed-signal: aggregate threshold = max(floor, this x aggregate "
                "baseline). Lower it if a --numLowRateAttackers run isn't tripping the alert.",
                aggMultiplier);
    cmd.AddValue("alertThresholdFactor",
                "Per-source threshold multiplier while a distributed alert is active",
                alertThresholdFactor);
    cmd.AddValue("enablePcap", "Write pcap captures", enablePcap);
    cmd.Parse(argc, argv);

    RngSeedManager::SetRun(run);
    Ptr<UniformRandomVariable> rng = CreateObject<UniformRandomVariable>();
    if (numClients == 0)
    {
        numClients = rng->GetInteger(2, 5);
    }
    if (numAttackers == 0)
    {
        numAttackers = rng->GetInteger(1, 3);
    }
    if (attackStart < 0.0)
    {
        // Random, but bounded so it always starts after the controller's baseline
        // warm-up (~8s) and leaves enough runway before simTime for the full
        // offence-escalation story (5s -> 20s -> blacklist, ~30s) to play out.
        attackStart = rng->GetValue(9.0, 14.0);
    }
    if (attackStop < 0.0)
    {
        attackStop = simTime - 1.0;
    }

    std::cout << "[ddos-advanced] run=" << run << " numClients=" << numClients
              << " numAttackers=" << numAttackers << " numLowRateAttackers=" << numLowRateAttackers
              << " attackStart=" << attackStart
              << " (+1 shared attacker & 1 innocent client on one shared port)\n";

    // --- Nodes ---
    NodeContainer clients;
    clients.Create(numClients);
    NodeContainer attackers;
    attackers.Create(numAttackers);
    NodeContainer lowRateAttackers; // distributed-attack pool (see numLowRateAttackers above)
    lowRateAttackers.Create(numLowRateAttackers);
    Ptr<Node> attackerShared = CreateObject<Node>();
    Ptr<Node> innocentShared = CreateObject<Node>();
    Ptr<Node> server = CreateObject<Node>();
    Ptr<Node> switchNode = CreateObject<Node>();
    Ptr<Node> controllerNode = CreateObject<Node>();

    // --- Data-plane link helpers ---
    CsmaHelper hostLink;
    hostLink.SetChannelAttribute("DataRate", StringValue(hostLinkRate));
    hostLink.SetChannelAttribute("Delay", TimeValue(MicroSeconds(2)));
    CsmaHelper serverLink;
    serverLink.SetChannelAttribute("DataRate", StringValue(serverLinkRate));
    serverLink.SetChannelAttribute("Delay", TimeValue(MicroSeconds(2)));

    NetDeviceContainer hostDevices; // IP-stack side, in assignment order
    NodeContainer hostNodes;        // parallel to hostDevices
    NetDeviceContainer switchPorts;

    // Dedicated one-host-per-port links: clients, attackers, then server.
    auto addDedicated = [&](Ptr<Node> h, bool isServer) {
        NodeContainer pair(h, switchNode);
        NetDeviceContainer link = (isServer ? serverLink : hostLink).Install(pair);
        hostDevices.Add(link.Get(0));
        switchPorts.Add(link.Get(1));
        hostNodes.Add(h);
    };
    for (uint32_t i = 0; i < numClients; i++)
    {
        addDedicated(clients.Get(i), false);
    }
    for (uint32_t i = 0; i < numAttackers; i++)
    {
        addDedicated(attackers.Get(i), false);
    }
    for (uint32_t i = 0; i < numLowRateAttackers; i++)
    {
        addDedicated(lowRateAttackers.Get(i), false);
    }
    uint32_t serverIndex = hostDevices.GetN();
    addDedicated(server, true);

    // One SHARED port carrying both an attacker and an innocent client.
    NodeContainer sharedSeg;
    sharedSeg.Add(switchNode);
    sharedSeg.Add(attackerShared);
    sharedSeg.Add(innocentShared);
    NetDeviceContainer sharedDevs = hostLink.Install(sharedSeg);
    switchPorts.Add(sharedDevs.Get(0)); // single switch port for the whole segment
    hostDevices.Add(sharedDevs.Get(1));
    hostNodes.Add(attackerShared);
    hostDevices.Add(sharedDevs.Get(2));
    hostNodes.Add(innocentShared);

    // --- SDN control plane (advanced controller) ---
    Ptr<OFSwitch13InternalHelper> of13 = CreateObject<OFSwitch13InternalHelper>();
    Ptr<SdnControllerAdv> controllerApp = CreateObject<SdnControllerAdv>();
    controllerApp->SetAttribute("MinThreshold", DoubleValue(threshold));
    controllerApp->SetAttribute("MonitorInterval", TimeValue(Seconds(monitorInterval)));
    controllerApp->SetAttribute("EnableMitigation", BooleanValue(mitigation));
    controllerApp->SetAttribute("TwoStage", BooleanValue(twoStage));
    controllerApp->SetAttribute("AggMultiplier", DoubleValue(aggMultiplier));
    controllerApp->SetAttribute("AlertThresholdFactor", DoubleValue(alertThresholdFactor));
    of13->InstallController(controllerNode, controllerApp);
    of13->InstallSwitch(switchNode, switchPorts);
    of13->CreateOpenFlowChannels();

    // --- IP stack on hosts only ---
    InternetStackHelper internet;
    internet.Install(hostNodes);

    TrafficControlHelper tch;
    tch.SetRootQueueDisc("ns3::FifoQueueDisc", "MaxSize", StringValue("2000p"));
    tch.Install(hostDevices);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ifaces = ipv4.Assign(hostDevices);
    Ipv4Address serverAddr = ifaces.GetAddress(serverIndex);

    uint16_t port = 9;
    PacketSinkHelper sink("ns3::UdpSocketFactory",
                          InetSocketAddress(Ipv4Address::GetAny(), port));
    ApplicationContainer sinkApp = sink.Install(server);
    sinkApp.Start(Seconds(0.5));
    sinkApp.Stop(Seconds(simTime));

    // --- Legitimate traffic: dedicated clients + the innocent shared client ---
    NodeContainer legit;
    legit.Add(clients);
    legit.Add(innocentShared);
    for (uint32_t i = 0; i < legit.GetN(); i++)
    {
        OnOffHelper onoff("ns3::UdpSocketFactory", InetSocketAddress(serverAddr, port));
        onoff.SetAttribute("DataRate", StringValue(perClientRate));
        onoff.SetAttribute("PacketSize", UintegerValue(clientPacketSize));
        onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        ApplicationContainer app = onoff.Install(legit.Get(i));
        app.Start(Seconds(1.0 + 0.1 * i));
        app.Stop(Seconds(simTime - 1.0));
    }

    // --- Attack traffic: dedicated attackers + the shared-port attacker ---
    NodeContainer attack;
    attack.Add(attackers);
    attack.Add(attackerShared);
    for (uint32_t i = 0; i < attack.GetN(); i++)
    {
        OnOffHelper flood("ns3::UdpSocketFactory", InetSocketAddress(serverAddr, port));
        flood.SetAttribute("DataRate", StringValue(attackRate));
        flood.SetAttribute("PacketSize", UintegerValue(attackPacketSize));
        flood.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        flood.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        ApplicationContainer app = flood.Install(attack.Get(i));
        app.Start(Seconds(attackStart));
        app.Stop(Seconds(attackStop));
    }

    // --- Distributed attack traffic: many devices, each BELOW the per-source
    //     threshold on its own -- only the aggregate-rate 2nd signal catches
    //     this (see sdn-controller-adv.h). Off by default (numLowRateAttackers=0).
    for (uint32_t i = 0; i < numLowRateAttackers; i++)
    {
        OnOffHelper trickle("ns3::UdpSocketFactory", InetSocketAddress(serverAddr, port));
        trickle.SetAttribute("DataRate", StringValue(lowRateAttackRate));
        trickle.SetAttribute("PacketSize", UintegerValue(attackPacketSize));
        trickle.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        trickle.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        ApplicationContainer app = trickle.Install(lowRateAttackers.Get(i));
        app.Start(Seconds(attackStart));
        app.Stop(Seconds(attackStop));
    }

    // --- Observability ---
    of13->EnableDatapathStats("switch-stats");
    if (enablePcap)
    {
        hostLink.EnablePcap("host", hostDevices);
    }
    FlowMonitorHelper flowmonHelper;
    Ptr<FlowMonitor> monitor = flowmonHelper.InstallAll();

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    monitor->CheckForLostPackets();
    monitor->SerializeToXmlFile("flowmon.xml", true, true);
    Simulator::Destroy();
    return 0;
}
