#include "sdn-controller-adv.h"

#include <algorithm>
#include <cmath>
#include <sstream>
#include <vector>

NS_LOG_COMPONENT_DEFINE("SdnControllerAdv");

namespace ns3
{

NS_OBJECT_ENSURE_REGISTERED(SdnControllerAdv);

SdnControllerAdv::SdnControllerAdv()
    : m_monitorInterval(Seconds(1.0)),
      m_minThreshold(500.0),
      m_baselineMultiplier(5.0),
      m_baselineWindow(Seconds(8.0)),
      m_smallPacketBytes(256),
      m_watchlistFactor(0.5),
      m_baseBlock(Seconds(5.0)),
      m_escalation(4.0),
      m_maxBlock(Seconds(120.0)),
      m_maxStrikes(3),
      m_stage2Delay(Seconds(0.5)),
      m_mitigationEnabled(true),
      m_twoStage(true),
      m_aggMultiplier(3.0),
      m_alertEntropyFloor(2.0),
      m_alertHoldTime(Seconds(5.0)),
      m_alertThresholdFactor(0.3)
{
    NS_LOG_FUNCTION(this);
}

SdnControllerAdv::~SdnControllerAdv()
{
    NS_LOG_FUNCTION(this);
}

TypeId
SdnControllerAdv::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::SdnControllerAdv")
            .SetParent<OFSwitch13Controller>()
            .SetGroupName("SdnDdosProject")
            .AddConstructor<SdnControllerAdv>()
            .AddAttribute("MonitorInterval", "How often to poll flow statistics.",
                          TimeValue(Seconds(1.0)),
                          MakeTimeAccessor(&SdnControllerAdv::m_monitorInterval), MakeTimeChecker())
            .AddAttribute("MinThreshold", "Floor for the adaptive packets/sec threshold.",
                          DoubleValue(500.0),
                          MakeDoubleAccessor(&SdnControllerAdv::m_minThreshold),
                          MakeDoubleChecker<double>())
            .AddAttribute("BaselineMultiplier", "threshold = max(MinThreshold, this x baseline).",
                          DoubleValue(5.0),
                          MakeDoubleAccessor(&SdnControllerAdv::m_baselineMultiplier),
                          MakeDoubleChecker<double>())
            .AddAttribute("BaselineWindow", "Warm-up duration used to learn the normal baseline.",
                          TimeValue(Seconds(8.0)),
                          MakeTimeAccessor(&SdnControllerAdv::m_baselineWindow), MakeTimeChecker())
            .AddAttribute("SmallPacketBytes",
                          "Average packet size (bytes) below which traffic looks flood-like.",
                          UintegerValue(256),
                          MakeUintegerAccessor(&SdnControllerAdv::m_smallPacketBytes),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("WatchlistFactor", "Threshold multiplier applied to watchlisted sources.",
                          DoubleValue(0.5),
                          MakeDoubleAccessor(&SdnControllerAdv::m_watchlistFactor),
                          MakeDoubleChecker<double>())
            .AddAttribute("BaseBlockDuration", "First-offence block hold-down duration.",
                          TimeValue(Seconds(5.0)),
                          MakeTimeAccessor(&SdnControllerAdv::m_baseBlock), MakeTimeChecker())
            .AddAttribute("EscalationFactor", "Block duration multiplier per repeat offence.",
                          DoubleValue(4.0),
                          MakeDoubleAccessor(&SdnControllerAdv::m_escalation),
                          MakeDoubleChecker<double>())
            .AddAttribute("MaxBlockDuration", "Cap on the escalating block duration.",
                          TimeValue(Seconds(120.0)),
                          MakeTimeAccessor(&SdnControllerAdv::m_maxBlock), MakeTimeChecker())
            .AddAttribute("MaxStrikes", "Offences before a source is permanently blacklisted.",
                          UintegerValue(3),
                          MakeUintegerAccessor(&SdnControllerAdv::m_maxStrikes),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("Stage2Delay", "Delay from coarse port block to surgical IP block.",
                          TimeValue(Seconds(0.5)),
                          MakeTimeAccessor(&SdnControllerAdv::m_stage2Delay), MakeTimeChecker())
            .AddAttribute("EnableMitigation", "Install DROP rules (false = detection only).",
                          BooleanValue(true),
                          MakeBooleanAccessor(&SdnControllerAdv::m_mitigationEnabled),
                          MakeBooleanChecker())
            .AddAttribute("TwoStage", "Use the port-block then IP-block two-stage response.",
                          BooleanValue(true),
                          MakeBooleanAccessor(&SdnControllerAdv::m_twoStage),
                          MakeBooleanChecker())
            .AddAttribute("AggMultiplier",
                          "Distributed-attack signal: aggThreshold = max(floor, this x "
                          "aggregate baseline). Catches many-device floods that are each "
                          "individually below the per-source threshold.",
                          DoubleValue(3.0),
                          MakeDoubleAccessor(&SdnControllerAdv::m_aggMultiplier),
                          MakeDoubleChecker<double>())
            .AddAttribute("AlertEntropyFloor",
                          "Min source entropy (bits) for traffic to count as 'spread across "
                          "many sources' rather than a concentrated few-source flood.",
                          DoubleValue(2.0),
                          MakeDoubleAccessor(&SdnControllerAdv::m_alertEntropyFloor),
                          MakeDoubleChecker<double>())
            .AddAttribute("AlertHoldTime", "How long a DISTRIBUTED_ALERT stays active.",
                          TimeValue(Seconds(5.0)),
                          MakeTimeAccessor(&SdnControllerAdv::m_alertHoldTime), MakeTimeChecker())
            .AddAttribute("AlertThresholdFactor",
                          "Per-source threshold multiplier while a distributed alert is active "
                          "(lower = every source is watched more strictly).",
                          DoubleValue(0.3),
                          MakeDoubleAccessor(&SdnControllerAdv::m_alertThresholdFactor),
                          MakeDoubleChecker<double>());
    return tid;
}

void
SdnControllerAdv::DoDispose()
{
    NS_LOG_FUNCTION(this);
    m_l2Table.clear();
    m_src.clear();
    if (m_filesOpen)
    {
        m_monitorFile.close();
        m_detectionFile.close();
        m_metricsFile.close();
        m_filesOpen = false;
    }
    OFSwitch13Controller::DoDispose();
}

void
SdnControllerAdv::HandshakeSuccessful(Ptr<const RemoteSwitch> swtch)
{
    NS_LOG_FUNCTION(this << swtch);
    uint64_t swDpId = swtch->GetDpId();

    // Table-miss: unmatched packets go to the controller (first 128 bytes, enough
    // for Ethernet/IP headers so we can learn the source MAC and IP).
    DpctlExecute(swDpId, "flow-mod cmd=add,table=0,prio=0 apply:output=ctrl:128");
    DpctlExecute(swDpId, "set-config miss=128");

    m_l2Table[swDpId] = L2Table_t();
    m_src[swDpId] = SrcMap_t();

    if (!m_filesOpen)
    {
        m_monitorFile.open("monitor-stats.csv");
        m_monitorFile << "TimeSec,DatapathId,SrcMac,SrcIp,Port,PacketsPerSec,BytesPerSec,"
                      << "AvgPktSize,Threshold,State\n";
        m_detectionFile.open("detections.csv");
        m_detectionFile << "TimeSec,DatapathId,SrcMac,SrcIp,Port,PacketsPerSec,AvgPktSize,"
                        << "Threshold,Offense,Event\n";
        m_metricsFile.open("metrics.csv");
        m_metricsFile << "TimeSec,ActiveSources,SourceEntropy,TopTalkerPct,BaselineRate,"
                      << "Threshold,BaselineReady,AggregateRate,AggregateThreshold,"
                      << "DistributedAlert\n";
        m_filesOpen = true;
    }

    // Start periodic per-source flow-statistics polling.
    Simulator::Schedule(m_monitorInterval, &SdnControllerAdv::RequestFlowStats, this, swDpId);
}

void
SdnControllerAdv::RequestFlowStats(uint64_t swDpId)
{
    NS_LOG_FUNCTION(this << swDpId);
    // OFPMP_FLOW: per-flow packet/byte counters. Because our learned forwarding
    // flows match on eth_src, summing these by eth_src gives a real per-source
    // rate even when several hosts share one switch port.
    DpctlExecute(swDpId, "stats-flow");
    Simulator::Schedule(m_monitorInterval, &SdnControllerAdv::RequestFlowStats, this, swDpId);
}

ofl_err
SdnControllerAdv::HandleMultipartReply(struct ofl_msg_multipart_reply_header* msg,
                                       Ptr<const RemoteSwitch> swtch,
                                       uint32_t xid)
{
    NS_LOG_FUNCTION(this << swtch << xid);
    if (msg->type == OFPMP_FLOW)
    {
        ProcessFlowStats(swtch->GetDpId(), (struct ofl_msg_multipart_reply_flow*)msg);
    }
    ofl_msg_free((struct ofl_msg_header*)msg, nullptr);
    return 0;
}

void
SdnControllerAdv::ProcessFlowStats(uint64_t swDpId, struct ofl_msg_multipart_reply_flow* reply)
{
    NS_LOG_FUNCTION(this << swDpId);

    const double interval = m_monitorInterval.GetSeconds();
    const double t = Simulator::Now().GetSeconds();
    L2Table_t& l2 = m_l2Table[swDpId];
    SrcMap_t& srcs = m_src[swDpId];

    // 1. Aggregate cumulative packet/byte counts per source MAC across all of
    //    that source's forwarding flows.
    std::map<Mac48Address, std::pair<uint64_t, uint64_t>> agg;
    for (size_t i = 0; i < reply->stats_num; i++)
    {
        struct ofl_flow_stats* fs = reply->stats[i];
        struct ofl_match_tlv* ethSrcTlv =
            oxm_match_lookup(OXM_OF_ETH_SRC, (struct ofl_match*)fs->match);
        if (!ethSrcTlv)
        {
            continue; // table-miss / IP-drop / port-drop flows carry no eth_src
        }
        Mac48Address mac;
        mac.CopyFrom(ethSrcTlv->value);
        agg[mac].first += fs->packet_count;
        agg[mac].second += fs->byte_count;
    }

    // 2. Per source: compute this interval's rate and average packet size, run
    //    detection, and record it.
    std::vector<double> deltas;
    double totalDelta = 0.0;
    for (const auto& kv : agg)
    {
        const Mac48Address& mac = kv.first;
        uint64_t curPkts = kv.second.first;
        uint64_t curBytes = kv.second.second;
        SrcState& s = srcs[mac];

        auto lit = l2.find(mac);
        if (lit != l2.end())
        {
            s.port = lit->second;
        }

        double pps = 0.0;
        double bps = 0.0;
        double avg = 0.0;
        bool skip = false;

        if (!s.seen)
        {
            // First time we see this source: set a reference point, no rate yet.
            s.seen = true;
            s.lastPkts = curPkts;
            s.lastBytes = curBytes;
            skip = true;
        }
        else if (curPkts < s.lastPkts || curBytes < s.lastBytes)
        {
            // Counter went backwards (flow expired and was re-installed): reset.
            s.lastPkts = curPkts;
            s.lastBytes = curBytes;
            skip = true;
        }

        if (!skip)
        {
            uint64_t dPkts = curPkts - s.lastPkts;
            uint64_t dBytes = curBytes - s.lastBytes;
            s.lastPkts = curPkts;
            s.lastBytes = curBytes;
            pps = dPkts / interval;
            bps = dBytes / interval;
            avg = (dPkts > 0) ? static_cast<double>(dBytes) / dPkts : 0.0;

            // Learn the baseline from normal traffic during the warm-up window.
            if (t <= m_baselineWindow.GetSeconds() && pps > m_baselineRate)
            {
                m_baselineRate = pps;
            }

            Evaluate(swDpId, mac, s, pps, avg);

            if (dPkts > 0)
            {
                deltas.push_back(static_cast<double>(dPkts));
                totalDelta += dPkts;
            }
        }

        std::string ipStr = s.hasIp ? [&] { std::ostringstream o; o << s.ip; return o.str(); }()
                                    : "unknown";
        std::string state = s.blacklisted ? "BLACKLISTED"
                            : s.blocked   ? "BLOCKED"
                            : s.watched   ? "WATCH"
                                          : "NORMAL";
        std::ostringstream macStr;
        macStr << mac;
        m_monitorFile << t << "," << swDpId << "," << macStr.str() << "," << ipStr << "," << s.port
                      << "," << pps << "," << bps << "," << avg << "," << ThresholdFor(s) << ","
                      << state << "\n";
    }

    // Learn the AGGREGATE (all-sources) baseline too, during the same warm-up
    // window -- this is what the distributed-attack 2nd signal compares against.
    double aggRateNow = totalDelta / interval;
    if (t <= m_baselineWindow.GetSeconds() && aggRateNow > m_aggBaselineRate)
    {
        m_aggBaselineRate = aggRateNow;
    }

    // 3. Mark the baseline ready once the warm-up ends.
    if (!m_baselineReady && t > m_baselineWindow.GetSeconds())
    {
        m_baselineReady = true;
        if (m_baselineRate <= 0.0)
        {
            m_baselineRate = m_minThreshold / std::max(1.0, m_baselineMultiplier);
        }
        if (m_aggBaselineRate <= 0.0)
        {
            m_aggBaselineRate = m_baselineRate;
        }
        NS_LOG_INFO("Baseline learned: " << m_baselineRate << " pps/source, "
                                         << m_aggBaselineRate << " pps aggregate, detection active.");
    }

    // 4. Global metrics: source entropy and top-talker share -- extra DDoS
    //    indicators (a flood concentrates traffic, collapsing entropy).
    double entropy = 0.0;
    double topShare = 0.0;
    if (totalDelta > 0)
    {
        for (double d : deltas)
        {
            double p = d / totalDelta;
            if (p > 0)
            {
                entropy -= p * std::log2(p);
            }
            topShare = std::max(topShare, p);
        }
    }
    double thr = m_baselineReady ? std::max(m_minThreshold, m_baselineMultiplier * m_baselineRate)
                                 : 0.0;

    // 5. Distributed (multi-device) attack 2nd signal: a single-attacker flood
    //    concentrates traffic on one source (entropy collapses, topShare spikes)
    //    and gets caught by the per-source check above. A flood split across
    //    many devices, each individually under the per-source threshold, looks
    //    the opposite: the AGGREGATE rate is anomalously high while entropy
    //    STAYS high (many roughly-equal contributors). That combination is what
    //    a fixed per-source rate check alone can never catch.
    double aggThr = m_baselineReady ? std::max(2.0 * m_minThreshold, m_aggMultiplier * m_aggBaselineRate)
                                    : 0.0;
    bool aggHigh = m_baselineReady && aggRateNow > aggThr;
    bool spread = entropy > m_alertEntropyFloor;
    if (aggHigh && spread)
    {
        if (!m_distributedAlert)
        {
            m_detectionFile << t << "," << swDpId << ",AGGREGATE,-,0," << aggRateNow << ",0,"
                            << aggThr << ",0,DISTRIBUTED_ALERT_ON\n";
            NS_LOG_WARN("Distributed attack suspected: aggregate " << aggRateNow << " pps across "
                                                                    << deltas.size()
                                                                    << " sources, entropy " << entropy);
        }
        m_distributedAlert = true;
        m_alertUntil = Simulator::Now() + m_alertHoldTime;
    }
    else if (m_distributedAlert && Simulator::Now() >= m_alertUntil)
    {
        m_distributedAlert = false;
        m_detectionFile << t << "," << swDpId << ",AGGREGATE,-,0," << aggRateNow << ",0," << aggThr
                        << ",0,DISTRIBUTED_ALERT_OFF\n";
    }

    m_metricsFile << t << "," << deltas.size() << "," << entropy << "," << (topShare * 100.0) << ","
                  << m_baselineRate << "," << thr << "," << (m_baselineReady ? 1 : 0) << ","
                  << aggRateNow << "," << aggThr << "," << (m_distributedAlert ? 1 : 0) << "\n";
}

double
SdnControllerAdv::ThresholdFor(const SrcState& s) const
{
    double base = std::max(m_minThreshold, m_baselineMultiplier * m_baselineRate);
    double thr = s.watched ? base * m_watchlistFactor : base;
    // 2nd detection step: while a distributed (multi-device) attack is
    // suspected, every source's own threshold is tightened so each
    // individually-small contributor trips the normal per-source path above.
    if (m_distributedAlert)
    {
        thr *= m_alertThresholdFactor;
    }
    return thr;
}

void
SdnControllerAdv::Evaluate(uint64_t swDpId, const Mac48Address& mac, SrcState& s, double pps,
                           double avgPktSize)
{
    // Don't act before the baseline is known, and don't re-trip a source that is
    // already mitigated (hysteresis -- the hold-down timer governs its release).
    if (!m_baselineReady || s.blocked || s.blacklisted)
    {
        return;
    }

    // Multi-signal rule: anomalous RATE *and* flood-like small packets.
    bool rateHigh = pps > ThresholdFor(s);
    bool smallPkts = avgPktSize > 0.0 && avgPktSize < m_smallPacketBytes;
    if (rateHigh && smallPkts)
    {
        Trip(swDpId, mac, s, pps, avgPktSize);
    }
}

void
SdnControllerAdv::Trip(uint64_t swDpId, const Mac48Address& mac, SrcState& s, double pps,
                       double avgPktSize)
{
    s.offenses++;

    double durSec =
        std::min(m_maxBlock.GetSeconds(),
                 m_baseBlock.GetSeconds() * std::pow(m_escalation, static_cast<double>(s.offenses - 1)));
    if (s.offenses >= m_maxStrikes)
    {
        s.blacklisted = true;
    }

    double t = Simulator::Now().GetSeconds();
    NS_LOG_WARN("Source " << mac << " flagged: " << pps << " pps, avg " << avgPktSize
                          << " B, offence #" << s.offenses);
    LogEvent(t, swDpId, mac, s, pps, avgPktSize, "DETECTED");

    if (!m_mitigationEnabled)
    {
        return; // detection-only experiment
    }

    s.blocked = true;
    s.blockedUntil = Simulator::Now() + Seconds(durSec);

    if (m_twoStage)
    {
        // Stage 1: coarse, immediate -- block the whole ingress port.
        BlockPort(swDpId, s.port);
        s.blockKind = BLOCK_PORT;
        LogEvent(t, swDpId, mac, s, pps, avgPktSize, "BLOCKED_PORT");
        // Stage 2: refine to a surgical per-source block shortly after.
        Simulator::Schedule(m_stage2Delay, &SdnControllerAdv::RefineToSourceBlock, this, swDpId,
                            mac);
    }
    else if (s.hasIp)
    {
        BlockIp(swDpId, s.ip);
        s.blockKind = BLOCK_IP;
        LogEvent(t, swDpId, mac, s, pps, avgPktSize, "ISOLATED_IP");
    }
    else
    {
        BlockMac(swDpId, mac);
        s.blockKind = BLOCK_MAC;
        LogEvent(t, swDpId, mac, s, pps, avgPktSize, "ISOLATED_MAC");
    }

    if (s.blacklisted)
    {
        LogEvent(t, swDpId, mac, s, pps, avgPktSize, "BLACKLISTED");
        // Permanent: no unblock is scheduled.
    }
    else
    {
        Simulator::Schedule(Seconds(durSec), &SdnControllerAdv::Unblock, this, swDpId, mac);
    }
}

void
SdnControllerAdv::RefineToSourceBlock(uint64_t swDpId, Mac48Address mac)
{
    auto dit = m_src.find(swDpId);
    if (dit == m_src.end())
    {
        return;
    }
    auto sit = dit->second.find(mac);
    if (sit == dit->second.end() || !sit->second.blocked)
    {
        return; // already released
    }
    SrcState& s = sit->second;
    double t = Simulator::Now().GetSeconds();

    if (s.hasIp)
    {
        BlockIp(swDpId, s.ip);
        UnblockPort(swDpId, s.port); // lift the coarse block so innocents recover
        s.blockKind = BLOCK_IP;
        LogEvent(t, swDpId, mac, s, 0, 0, "ISOLATED_IP");
    }
    else
    {
        BlockMac(swDpId, mac);
        UnblockPort(swDpId, s.port);
        s.blockKind = BLOCK_MAC;
        LogEvent(t, swDpId, mac, s, 0, 0, "ISOLATED_MAC");
    }
}

void
SdnControllerAdv::Unblock(uint64_t swDpId, Mac48Address mac)
{
    auto dit = m_src.find(swDpId);
    if (dit == m_src.end())
    {
        return;
    }
    auto sit = dit->second.find(mac);
    if (sit == dit->second.end())
    {
        return;
    }
    SrcState& s = sit->second;
    if (!s.blocked || s.blacklisted)
    {
        return; // blacklisted sources stay blocked forever
    }

    switch (s.blockKind)
    {
    case BLOCK_PORT:
        UnblockPort(swDpId, s.port);
        break;
    case BLOCK_IP:
        UnblockIp(swDpId, s.ip);
        break;
    case BLOCK_MAC:
        UnblockMac(swDpId, mac);
        break;
    default:
        break;
    }

    s.blocked = false;
    s.blockKind = BLOCK_NONE;
    s.watched = true; // reduced threshold from now on -- re-offence caught faster
    s.seen = false;   // re-baseline the counter after the forwarding flow re-installs

    double t = Simulator::Now().GetSeconds();
    LogEvent(t, swDpId, mac, s, 0, 0, "UNBLOCKED");
}

void
SdnControllerAdv::BlockPort(uint64_t swDpId, uint32_t portNo)
{
    std::ostringstream cmd;
    cmd << "flow-mod cmd=add,table=0,prio=250 in_port=" << portNo;
    DpctlExecute(swDpId, cmd.str());
}

void
SdnControllerAdv::UnblockPort(uint64_t swDpId, uint32_t portNo)
{
    std::ostringstream cmd;
    cmd << "flow-mod cmd=del,table=0 in_port=" << portNo;
    DpctlExecute(swDpId, cmd.str());
}

void
SdnControllerAdv::BlockIp(uint64_t swDpId, Ipv4Address ip)
{
    std::ostringstream cmd;
    cmd << "flow-mod cmd=add,table=0,prio=260 eth_type=0x800,ip_src=" << ip;
    DpctlExecute(swDpId, cmd.str());
}

void
SdnControllerAdv::UnblockIp(uint64_t swDpId, Ipv4Address ip)
{
    std::ostringstream cmd;
    cmd << "flow-mod cmd=del,table=0 eth_type=0x800,ip_src=" << ip;
    DpctlExecute(swDpId, cmd.str());
}

void
SdnControllerAdv::BlockMac(uint64_t swDpId, Mac48Address mac)
{
    std::ostringstream cmd;
    cmd << "flow-mod cmd=add,table=0,prio=260 eth_src=" << mac;
    DpctlExecute(swDpId, cmd.str());
}

void
SdnControllerAdv::UnblockMac(uint64_t swDpId, Mac48Address mac)
{
    std::ostringstream cmd;
    cmd << "flow-mod cmd=del,table=0 eth_src=" << mac;
    DpctlExecute(swDpId, cmd.str());
}

void
SdnControllerAdv::LogEvent(double t, uint64_t swDpId, const Mac48Address& mac, const SrcState& s,
                           double pps, double avgPktSize, const std::string& event)
{
    std::ostringstream macStr;
    macStr << mac;
    std::string ipStr = s.hasIp ? [&] { std::ostringstream o; o << s.ip; return o.str(); }()
                                : "unknown";
    m_detectionFile << t << "," << swDpId << "," << macStr.str() << "," << ipStr << "," << s.port
                    << "," << pps << "," << avgPktSize << "," << ThresholdFor(s) << ","
                    << s.offenses << "," << event << "\n";
}

ofl_err
SdnControllerAdv::HandlePacketIn(struct ofl_msg_packet_in* msg,
                                 Ptr<const RemoteSwitch> swtch,
                                 uint32_t xid)
{
    NS_LOG_FUNCTION(this << swtch << xid);

    uint64_t swDpId = swtch->GetDpId();
    uint32_t outPort = OFPP_FLOOD;

    if (msg->reason != OFPR_NO_MATCH)
    {
        NS_LOG_WARN("Unexpected packet-in reason, ignoring.");
        ofl_msg_free((struct ofl_msg_header*)msg, nullptr);
        return 0;
    }

    uint32_t inPort;
    struct ofl_match_tlv* inPortTlv =
        oxm_match_lookup(OXM_OF_IN_PORT, (struct ofl_match*)msg->match);
    memcpy(&inPort, inPortTlv->value, OXM_LENGTH(OXM_OF_IN_PORT));

    Mac48Address srcMac;
    struct ofl_match_tlv* ethSrcTlv =
        oxm_match_lookup(OXM_OF_ETH_SRC, (struct ofl_match*)msg->match);
    srcMac.CopyFrom(ethSrcTlv->value);

    Mac48Address dstMac;
    struct ofl_match_tlv* ethDstTlv =
        oxm_match_lookup(OXM_OF_ETH_DST, (struct ofl_match*)msg->match);
    dstMac.CopyFrom(ethDstTlv->value);

    L2Table_t& l2Table = m_l2Table[swDpId];
    if (l2Table.find(srcMac) == l2Table.end())
    {
        l2Table[srcMac] = inPort;
        NS_LOG_DEBUG("Learned " << srcMac << " on port " << inPort);
    }

    // Keep per-source bookkeeping in step: remember this source's ingress port
    // and, if this is an IPv4 packet, learn its source IP so a later stage-2
    // mitigation can target the exact IP address.
    SrcState& s = m_src[swDpId][srcMac];
    s.port = inPort;
    // Learn the source IP if this packet-in carries one (IPv4 packets). The
    // OXM value is stored host-order (same as in_port above), and the 4 address
    // octets are in a.b.c.d order, so assemble them directly.
    struct ofl_match_tlv* ipSrcTlv =
        oxm_match_lookup(OXM_OF_IPV4_SRC, (struct ofl_match*)msg->match);
    if (ipSrcTlv)
    {
        uint8_t b[4];
        memcpy(b, ipSrcTlv->value, 4);
        s.ip = Ipv4Address((uint32_t(b[0]) << 24) | (uint32_t(b[1]) << 16) |
                           (uint32_t(b[2]) << 8) | uint32_t(b[3]));
        s.hasIp = true;
    }

    // Learn/forward on the (src, dst) pair -- same reasoning as the baseline
    // controller: keeps both directions reaching the controller so every MAC is
    // learned, and these per-(src,dst) flows are what the flow-stats detector
    // later counts by eth_src.
    if (!dstMac.IsBroadcast())
    {
        auto it = l2Table.find(dstMac);
        if (it != l2Table.end())
        {
            outPort = it->second;
            std::ostringstream cmd;
            cmd << "flow-mod cmd=add,table=0,idle=10,flags=0x0001"
                << ",prio=100 eth_src=" << srcMac << ",eth_dst=" << dstMac
                << " apply:output=" << outPort;
            DpctlExecute(swDpId, cmd.str());
        }
    }

    struct ofl_msg_packet_out reply;
    reply.header.type = OFPT_PACKET_OUT;
    reply.buffer_id = msg->buffer_id;
    reply.in_port = inPort;
    reply.data_length = 0;
    reply.data = nullptr;
    if (msg->buffer_id == NO_BUFFER)
    {
        reply.data_length = msg->data_length;
        reply.data = msg->data;
    }

    auto action = (struct ofl_action_output*)xmalloc(sizeof(struct ofl_action_output));
    action->header.type = OFPAT_OUTPUT;
    action->port = outPort;
    action->max_len = 0;
    reply.actions_num = 1;
    reply.actions = (struct ofl_action_header**)&action;

    SendToSwitch(swtch, (struct ofl_msg_header*)&reply, xid);
    free(action);

    ofl_msg_free((struct ofl_msg_header*)msg, nullptr);
    return 0;
}

ofl_err
SdnControllerAdv::HandleFlowRemoved(struct ofl_msg_flow_removed* msg,
                                    Ptr<const RemoteSwitch> swtch,
                                    uint32_t xid)
{
    NS_LOG_FUNCTION(this << swtch << xid);
    // A single (src,dst) fast-path flow idled out; our MAC/IP learning and
    // reputation state deliberately persist for the session.
    ofl_msg_free_flow_removed(msg, true, nullptr);
    return 0;
}

} // namespace ns3
