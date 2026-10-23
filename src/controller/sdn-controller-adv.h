#ifndef SDN_CONTROLLER_ADV_H
#define SDN_CONTROLLER_ADV_H

#include <ns3/ipv4-address.h>
#include <ns3/ofswitch13-module.h>

#include <fstream>
#include <map>

namespace ns3
{

/**
 * Advanced SDN controller (project v2).
 *
 * This is the enhanced controller that answers the review feedback. It keeps
 * the same spirit as the original SdnController -- a learning switch plus a
 * rule/threshold detector -- but upgrades five things:
 *
 *  1. PER-SOURCE detection. The original polled OpenFlow PORT statistics and
 *     treated "port == source", which only holds when every host has its own
 *     switch port. Here the controller polls FLOW statistics (OFPMP_FLOW) and
 *     aggregates packet/byte counters by the flow's eth_src, so it measures a
 *     real per-source rate even when several hosts share one switch port.
 *
 *  2. MULTI-SIGNAL detection. A source is flagged only when BOTH its packet
 *     rate is anomalous AND its average packet size is small (floods use tiny
 *     packets; legitimate traffic does not). This cuts false positives from a
 *     legitimate traffic burst. A global source-entropy / top-talker metric is
 *     also logged each poll for analysis.
 *
 *  3. ADAPTIVE threshold. Instead of a hard-coded packets/sec constant, the
 *     controller learns a baseline during the first few seconds and flags
 *     traffic above (BaselineMultiplier x baseline), floored at MinThreshold.
 *     (There is no international standard pps value for "this is a DDoS" -- it
 *     is inherently relative to the victim's normal load, which is exactly what
 *     a baseline-relative threshold captures.)
 *
 *  4. TWO-STAGE mitigation. On first detection the controller installs a fast,
 *     coarse DROP on the attacker's ingress PORT (stop the bleeding), then a
 *     moment later refines it to a surgical per-IP DROP and lifts the port
 *     block -- so innocent hosts sharing that port recover.
 *
 *  5. PENALTIES + smarter unblock. Each source has a reputation record. A block
 *     is held for a minimum, escalating duration (5s, then x4, ... capped), not
 *     lifted the instant traffic dips. A repeat offender's block grows each
 *     time, and after MaxStrikes it is permanently blacklisted. After an
 *     unblock the source stays on a watchlist with a reduced threshold so a
 *     re-offense is caught faster.
 *
 *  6. DISTRIBUTED-attack second signal. Per-source detection alone misses an
 *     attacker that floods from many devices, each individually below the
 *     per-source threshold (the real-world case: Microsoft reported a 3.47
 *     Tbps attack in Nov 2021 from ~10,000 sources, none remarkable on its
 *     own). Each poll also compares the TOTAL rate across all sources to a
 *     learned aggregate baseline; if the total is anomalously high *and*
 *     source entropy stays high (many sources contributing roughly equally,
 *     not one or two dominating -- the opposite of a concentrated flood),
 *     the controller raises a time-limited DISTRIBUTED_ALERT that temporarily
 *     tightens every source's own threshold, so each contributing device
 *     trips the existing per-source detector on the very next poll instead of
 *     hiding under an individually-small rate.
 *
 * Rate-limiting with OpenFlow meters (instead of an outright drop) is left as
 * documented future scope.
 */
class SdnControllerAdv : public OFSwitch13Controller
{
  public:
    SdnControllerAdv();
    ~SdnControllerAdv() override;

    static TypeId GetTypeId();
    void DoDispose() override;

    ofl_err HandlePacketIn(struct ofl_msg_packet_in* msg,
                           Ptr<const RemoteSwitch> swtch,
                           uint32_t xid) override;

    ofl_err HandleFlowRemoved(struct ofl_msg_flow_removed* msg,
                              Ptr<const RemoteSwitch> swtch,
                              uint32_t xid) override;

    ofl_err HandleMultipartReply(struct ofl_msg_multipart_reply_header* msg,
                                 Ptr<const RemoteSwitch> swtch,
                                 uint32_t xid) override;

  protected:
    void HandshakeSuccessful(Ptr<const RemoteSwitch> swtch) override;

  private:
    /** How a source is currently mitigated, so we can later undo the same thing. */
    enum BlockKind
    {
        BLOCK_NONE = 0,
        BLOCK_PORT, //!< Coarse stage-1 block on the ingress port.
        BLOCK_IP,   //!< Surgical stage-2 block on the source IP.
        BLOCK_MAC   //!< Fallback stage-2 block on the source MAC (IP unknown).
    };

    /** Everything the controller knows and decides about one source host. */
    struct SrcState
    {
        // --- monitoring (for per-source rate from flow stats) ---
        uint64_t lastPkts = 0;  //!< Cumulative packets at previous poll.
        uint64_t lastBytes = 0; //!< Cumulative bytes at previous poll.
        bool seen = false;      //!< Have we taken a first baseline sample yet?
        uint32_t port = 0;      //!< Last known ingress switch port for this MAC.
        Ipv4Address ip;         //!< Learned source IP (if any).
        bool hasIp = false;     //!< Whether ip is valid.

        // --- reputation / mitigation ---
        uint32_t offenses = 0;      //!< How many times this source has tripped.
        bool blocked = false;       //!< Currently mitigated?
        bool blacklisted = false;   //!< Permanently blocked (repeat offender)?
        bool watched = false;       //!< On the watchlist (reduced threshold)?
        BlockKind blockKind = BLOCK_NONE;
        Time blockedUntil;          //!< Hold-down: earliest time we may unblock.
    };

    typedef std::map<Mac48Address, uint32_t> L2Table_t;
    typedef std::map<Mac48Address, SrcState> SrcMap_t;

    std::map<uint64_t, L2Table_t> m_l2Table; //!< dpid -> (MAC -> port).
    std::map<uint64_t, SrcMap_t> m_src;      //!< dpid -> (MAC -> per-source state).

    // --- adaptive threshold state ---
    double m_baselineRate = 0.0; //!< Peak legitimate per-source rate seen in the warm-up.
    bool m_baselineReady = false;

    // --- distributed (multi-device) attack detection: a 2nd signal that does
    //     not depend on any single source's own rate ---
    double m_aggBaselineRate = 0.0; //!< Peak TOTAL legitimate rate (all sources) in warm-up.
    bool m_distributedAlert = false; //!< Currently in a heightened-alert window?
    Time m_alertUntil;               //!< Alert auto-clears once past this time.

    // --- configurable attributes ---
    Time m_monitorInterval;
    double m_minThreshold;       //!< Floor for the adaptive threshold (pps).
    double m_baselineMultiplier; //!< threshold = max(min, mult * baseline).
    Time m_baselineWindow;       //!< Warm-up duration to learn the baseline.
    uint32_t m_smallPacketBytes; //!< Avg packet size below this looks flood-like.
    double m_watchlistFactor;    //!< Threshold multiplier for watchlisted sources.
    Time m_baseBlock;            //!< First-offense block duration.
    double m_escalation;         //!< Block duration multiplier per repeat offense.
    Time m_maxBlock;             //!< Cap on block duration.
    uint32_t m_maxStrikes;       //!< Offenses before a permanent blacklist.
    Time m_stage2Delay;          //!< Port-block -> IP-block refinement delay.
    bool m_mitigationEnabled;    //!< Install drop rules at all?
    bool m_twoStage;             //!< Use the port->IP two-stage path?

    // --- distributed-attack 2nd signal: configurable attributes ---
    double m_aggMultiplier;      //!< aggThreshold = max(floor, this x aggBaseline).
    double m_alertEntropyFloor;  //!< Min source entropy (bits) to call traffic "spread out".
    Time m_alertHoldTime;        //!< How long a DISTRIBUTED_ALERT stays active after last trigger.
    double m_alertThresholdFactor; //!< Per-source threshold multiplier while alert is active.

    // --- output files ---
    std::ofstream m_monitorFile;
    std::ofstream m_detectionFile;
    std::ofstream m_metricsFile;
    bool m_filesOpen = false;

    /** Ask a switch for all flow statistics, then reschedule itself. */
    void RequestFlowStats(uint64_t swDpId);

    /** Aggregate a flow-stats reply by source, log, and run detection. */
    void ProcessFlowStats(uint64_t swDpId, struct ofl_msg_multipart_reply_flow* reply);

    /** The detection decision for one source this poll. */
    void Evaluate(uint64_t swDpId, const Mac48Address& mac, SrcState& s,
                  double pps, double avgPktSize);

    /** Act on a confirmed attacker: count the offense and start mitigation. */
    void Trip(uint64_t swDpId, const Mac48Address& mac, SrcState& s,
              double pps, double avgPktSize);

    /** Stage 2: replace the coarse port block with a surgical per-IP (or MAC) block. */
    void RefineToSourceBlock(uint64_t swDpId, Mac48Address mac);

    /** Hold-down expired: lift mitigation (unless blacklisted) and watchlist the source. */
    void Unblock(uint64_t swDpId, Mac48Address mac);

    // Low-level flow-mod helpers.
    void BlockPort(uint64_t swDpId, uint32_t portNo);
    void UnblockPort(uint64_t swDpId, uint32_t portNo);
    void BlockIp(uint64_t swDpId, Ipv4Address ip);
    void UnblockIp(uint64_t swDpId, Ipv4Address ip);
    void BlockMac(uint64_t swDpId, Mac48Address mac);
    void UnblockMac(uint64_t swDpId, Mac48Address mac);

    /** Current detection threshold for a source (lower if watchlisted). */
    double ThresholdFor(const SrcState& s) const;

    /** Write one CSV event row to detections.csv. */
    void LogEvent(double t, uint64_t swDpId, const Mac48Address& mac, const SrcState& s,
                  double pps, double avgPktSize, const std::string& event);
};

} // namespace ns3

#endif /* SDN_CONTROLLER_ADV_H */
