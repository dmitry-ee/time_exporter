// Copyright 2015 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build linux darwin
// +build !nochrony

package collector

import (
	"encoding/json"
	"github.com/facebookincubator/ntp/ntpcheck/checker"
	"github.com/facebookincubator/ntp/protocol/chrony"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/ulule/deepcopier"
	"gopkg.in/alecthomas/kingpin.v2"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	chronySubsystem = "chrony"
)

var (
	chronyAddress         = kingpin.Flag("collector.chrony.address", "chronyd address (could be socket or host:port)").Default("127.0.0.1:323").String()
	chronyLogResponseJSON = kingpin.Flag("collector.chrony.log-response-json", "Log chrony socket response as json through the debug level").Default("true").Bool()
)

type NTPCheckResultE struct {
	// parsed from SystemStatusWord
	LI          uint8					`deepcopier:"field:LI"`
	LIDesc      string					`deepcopier:"field:LIDesc"`
	ClockSource string					`deepcopier:"field:ClockSource"`
	Correction  float64					`deepcopier:"field:Correction"`
	Event       string					`deepcopier:"field:Event"`
	EventCount  uint8					`deepcopier:"field:EventCount"`
	// data parsed from System Variables
	SysVars *checker.SystemVariables	`deepcopier:"field:SysVars"`
	// map of peers with data from PeerStatusWord and Peer Variables
	Peers map[uint16]*PeerE				`deepcopier:"field:Peers"`
}

type PeerE struct {
	// from PeerStatusWord
	Configured   bool	`deepcopier:"field:Configured"`
	AuthPossible bool	`deepcopier:"field:AuthPossible"`
	Authentic    bool	`deepcopier:"field:Authentic"`
	Reachable    bool	`deepcopier:"field:Reachable"`
	Broadcast    bool	`deepcopier:"field:Broadcast"`
	Selection    uint8	`deepcopier:"field:Selection"`
	Condition    string	`deepcopier:"field:Condition"`
	// from variables
	SRCAdr     string	`deepcopier:"field:SRCAdr"`
	SRCPort    int		`deepcopier:"field:SRCPort"`
	DSTAdr     string	`deepcopier:"field:DSTAdr"`
	DSTPort    int		`deepcopier:"field:DSTPort"`
	Leap       int		`deepcopier:"field:Leap"`
	Stratum    int		`deepcopier:"field:Stratum"`
	Precision  int		`deepcopier:"field:Precision"`
	RootDelay  float64	`deepcopier:"field:RootDelay"`
	RootDisp   float64	`deepcopier:"field:RootDisp"`
	RefID      string	`deepcopier:"field:RefID"`
	RefTime    string	`deepcopier:"field:RefTime"`
	Reach      uint8	`deepcopier:"field:Reach"`
	Unreach    int		`deepcopier:"field:Unreach"`
	HMode      int		`deepcopier:"field:HMode"`
	PMode      int		`deepcopier:"field:PMode"`
	HPoll      int		`deepcopier:"field:HPoll"`
	PPoll      int		`deepcopier:"field:PPoll"`
	Headway    int		`deepcopier:"field:Headway"`
	Flash      uint16	`deepcopier:"field:Flash"`
	Flashers   []string	`deepcopier:"field:Flashers"`
	Offset     float64	`deepcopier:"field:Offset"`
	Delay      float64	`deepcopier:"field:Delay"`
	Dispersion float64	`deepcopier:"field:Dispersion"`
	Jitter     float64	`deepcopier:"field:Jitter"`
	Xleave     float64	`deepcopier:"field:Xleave"`
	Rec        string	`deepcopier:"field:Rec"`
	FiltDelay  string	`deepcopier:"field:FiltDelay"`
	FiltOffset string	`deepcopier:"field:FiltOffset"`
	FiltDisp   string	`deepcopier:"field:FiltDisp"`
	// from sourceStats
	NSamples   		uint32
	NRuns 			uint32
	SpanSeconds 	uint32
	StdDev 			float64
	ResidFreq 		float64
	SkewFreq 		float64
	EstOffset 		float64
	EstOffsetError 	float64
}

type chronyCollector struct {

	// tracking response
	trackingLI, //int
	// trackingLIDesc, //str -> str rep of LI
	trackingClockSource, //str -> always shown as 1
	trackingCorrection, //float
	// trackingEvent, //str
	// trackingEventCount, //int

	// tracking as sysvars
	// trackingVersion, //str
	// trackingProcessor, //str
	// trackingSystem, //str
	// trackingLeap, //int -> same value as LI
	trackingStratum, //int
	trackingPrecision, //int
	trackingRootDelay, //float
	trackingRootDisp, //float
	// trackingPeer, //int
	// trackingTC, //int
	// trackingMinTC, //int
	// trackingClock, //str
	trackingRefID, //str -> parsed as float
	trackingRefTime, //str -> parsed as float
	trackingOffset, //float
	// trackingSysJitter, //int
	trackingFrequency, //float
	// trackingClkWander, //int
	// trackingClkJitter, //int
	// trackingTai, //int

	// sources response
	sourcesPeerConfigured, //bool -> parsed as 1/0
	sourcesPeerAuthPossible, //bool -> parsed as 1/0
	sourcesPeerAuthentic, //bool -> parsed as 1/0
	sourcesPeerReachable, //bool -> parsed as 1/0
	sourcesPeerBroadcast, //bool -> parsed as 1/0
	sourcesPeerSelection, //int
	// sourcesPeerCondition, //str -> str rep of selection
	// sourcesPeerSRCAdr, //str
	// sourcesPeerSRCPort, //int
	// sourcesPeerDSTAdr, //str
	// sourcesPeerDSTPort, //int
	sourcesPeerLeap, //int
	sourcesPeerStratum, //int
	sourcesPeerPrecision, //int
	sourcesPeerRootDelay, //float
	sourcesPeerRootDisp, //float
	sourcesPeerRefID, //str -> parsed as float
	sourcesPeerRefTime, //str -> parsed as float
	sourcesPeerReach, //int
	sourcesPeerUnreach, //int
	sourcesPeerHMode, //int
	sourcesPeerPMode, //int
	sourcesPeerHPoll, //int
	sourcesPeerPPoll, //int
	sourcesPeerHeadway, //int
	// sourcesPeerFlash, //int
	sourcesPeerOffset, //float
	//sourcesPeerDelay, //float
	//sourcesPeerDispersion, //float
	sourcesPeerJitter, //float
	sourcesPeerXleave, //float
	// sourcesPeerRec, //str
	// sourcesPeerFiltDelay, //str
	// sourcesPeerFiltOffset, //str
	// sourcesPeerFiltDisp, //str
	sourceStatsNSamples, //int
	sourceStatsNRuns, //int
	sourceStatsSpanSeconds, //int
	sourceStatsStdDev, //float
	sourceStatsResidFreq, //float
	sourceStatsSkewFreq, //float
	sourceStatsEstOffset, //float
	sourceStatsEstOffsetError, //float

	// manually added metrics
	sourcesPeerCount typedDesc //int

	logger log.Logger
}

func init() {
	registerCollector("chrony", true, NewChronyCollector)
}

func NewChronyCollector(logger log.Logger) (Collector, error) {
	peerLabels := []string{"addr"}

	return &chronyCollector{
		trackingLI:          typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "tracking_leap_indicator"), "Tracking Leap Indicator. 0 - no warning, 3 - alarm", []string{"desc"}, nil), prometheus.GaugeValue},                     //int
		trackingClockSource: typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "tracking_clock_source"), "Clock Source, str value in 'src' label, value always 1.", []string{"src"}, nil), prometheus.GaugeValue},                   //int
		trackingCorrection:  typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "tracking_correction"), "Current correction value.", nil, nil), prometheus.GaugeValue},                                                               //float
		trackingStratum:     typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "tracking_stratum"), "The stratum indicates how many hops away from a computer with an attached reference clock we are.", nil, nil), prometheus.GaugeValue},                                                                                                    //int
		trackingPrecision:   typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "tracking_precision"), "Current precision.", nil, nil), prometheus.GaugeValue},                                                                       //int
		trackingRootDelay:   typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "tracking_root_delay"), "Total of the network path delays to the stratum-1 computer from which the computer is ultimately synchronized.", nil, nil), prometheus.GaugeValue},                                                                                    //float
		trackingRootDisp:    typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "tracking_root_disp"), "Total dispersion accumulated through all the computers back to the stratum-1 computer from which the computer is ultimately synchronized.", nil, nil), prometheus.GaugeValue},                                                          //float
		trackingRefID:       typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "tracking_ref_id"), "Encoded address of connected machine (if available).", nil, nil), prometheus.GaugeValue},                                        //float
		trackingRefTime:     typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "tracking_ref_time"), "The time (UTC) at which the last measurement from the reference source was processed.", nil, nil), prometheus.GaugeValue},     //float
		trackingOffset:      typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "tracking_offset"), "The estimated local offset on the last clock update.", nil, nil), prometheus.GaugeValue},                                        //float
		trackingFrequency:   typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "tracking_frequency"), "The rate by which the system’s clock would be wrong if chronyd was not correcting it. It is expressed in ppm (parts per million). For example, a value of 1 ppm would mean that when the system’s clock thinks it has advanced 1 second, it has actually advanced by 1.000001 seconds relative to true time.", nil, nil), prometheus.GaugeValue}, //float

		sourcesPeerSelection:    typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_selection"), "State of the source (int code of *|+|-|?|x|~). str value in 'desc' label. See: https://github.com/facebookincubator/ntp/blob/master/protocol/chrony/packet.go#L81", append(peerLabels, "desc"), nil), prometheus.GaugeValue}, //int
		sourcesPeerOffset:       typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_offset"), "Offset of last update.", peerLabels, nil), prometheus.GaugeValue},                                                     //float
		//sourcesPeerDelay:        typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_delay"), "Delay to peer.", peerLabels, nil), prometheus.GaugeValue},                                                              //float
		//sourcesPeerDispersion:   typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_dispersion"), "Peer dispersion.", peerLabels, nil), prometheus.GaugeValue},                                                       //float
		sourcesPeerJitter:       typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_jitter"), "Peer jitter.", peerLabels, nil), prometheus.GaugeValue},                                                               //float
		sourcesPeerRefID:        typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_ref_id"), "Peer refId (see tracking_ref_id).", peerLabels, nil), prometheus.GaugeValue},                                          //float
		sourcesPeerRefTime:      typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_ref_time"), "Peer refTime (see tracking_ref_time).", peerLabels, nil), prometheus.GaugeValue},                                    //float
		sourcesPeerRootDelay:    typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_root_delay"), "Peer root delay (see tracking_root_delay).", peerLabels, nil), prometheus.GaugeValue},                             //float
		sourcesPeerRootDisp:     typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_root_disp"), "Peer root dispersion (see tracking_root_disp).", peerLabels, nil), prometheus.GaugeValue},                          //float
		sourcesPeerConfigured:   typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_peer_configured"), "Configured flag (1|0).", peerLabels, nil), prometheus.GaugeValue},                                            //bool
		sourcesPeerAuthPossible: typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_auth_possible"), "AuthPosible flag (1|0).", peerLabels, nil), prometheus.GaugeValue},                                             //bool
		sourcesPeerAuthentic:    typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_authentic"), "Authenticatd flag (0|1).", peerLabels, nil), prometheus.GaugeValue},                                                //bool
		sourcesPeerReachable:    typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_reachable"), "Reachability (1 if sourceReply Reachability flag == 255 else 0).", peerLabels, nil), prometheus.GaugeValue},        //bool
		sourcesPeerBroadcast:    typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_broadcast"), "Broadcast flag (1|0).", peerLabels, nil), prometheus.GaugeValue},                                                   //bool
		sourcesPeerLeap:         typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_leap"), "Peer leap value (see tracking_leap_indicator).", peerLabels, nil), prometheus.GaugeValue},                               //int
		sourcesPeerStratum:      typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_stratum"), "Peer startum (see tracking_stratum).", peerLabels, nil), prometheus.GaugeValue},                                      //int
		sourcesPeerPrecision:    typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_precision"), "Peer precision (see tracking_precision).", peerLabels, nil), prometheus.GaugeValue},                                //int
		sourcesPeerReach:        typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_reach"), "Int value of sourceReply Reachability flag (see sources_peer_reachable).", peerLabels, nil), prometheus.GaugeValue},    //int
		sourcesPeerUnreach:      typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_unreach"), "Unreach flag from .", peerLabels, nil), prometheus.GaugeValue},                                                       //int
		sourcesPeerHMode:        typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_hmode"), "Hmode value from source data.", peerLabels, nil), prometheus.GaugeValue},                                               //int
		sourcesPeerPMode:        typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_pmode"), "Pmode value from source data.", peerLabels, nil), prometheus.GaugeValue},                                               //int
		sourcesPeerHPoll:        typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_hpoll"), "Hpoll value from source data.", peerLabels, nil), prometheus.GaugeValue},                                               //int
		sourcesPeerPPoll:        typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_ppoll"), "Ppoll value from source data.", peerLabels, nil), prometheus.GaugeValue},                                               //int
		sourcesPeerHeadway:      typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_headway"), "Headway value from source data.", peerLabels, nil), prometheus.GaugeValue},                                           //int
		sourcesPeerXleave:       typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_xleave"), "Xleave value from source data.", peerLabels, nil), prometheus.GaugeValue},                                             //float

		sourceStatsNSamples:		typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sourcestats_nsamples"), "Number of sample points in measurement set.", peerLabels, nil), prometheus.GaugeValue},                                               //int
		sourceStatsNRuns:        	typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sourcestats_nruns"), "Number of residual runs with same sign.", peerLabels, nil), prometheus.GaugeValue},                                               //int
		sourceStatsSpanSeconds:     typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sourcestats_span_seconds"), "Length of measurement set (time).", peerLabels, nil), prometheus.GaugeValue},                                             //float
		sourceStatsStdDev:       	typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sourcestats_std_dev_seconds"), "Est. sample standard deviation.", peerLabels, nil), prometheus.GaugeValue},                                             //float
		sourceStatsResidFreq:       typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sourcestats_residential_freq"), "Est. clock freq error (ppm).", peerLabels, nil), prometheus.GaugeValue},                                             //float
		sourceStatsSkewFreq:       	typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sourcestats_skew_freq"), "Est. error in freq.", peerLabels, nil), prometheus.GaugeValue},                                             //float
		sourceStatsEstOffset:       typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sourcestats_est_offset_seconds"), "Est. offset on the samples.", peerLabels, nil), prometheus.GaugeValue},                                             //float
		sourceStatsEstOffsetError:  typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sourcestats_est_offset_error_seconds"), "Est. error in offset.", peerLabels, nil), prometheus.GaugeValue},                                             //float

		sourcesPeerCount: typedDesc{prometheus.NewDesc(prometheus.BuildFQName(namespace, chronySubsystem, "sources_peer_count"), "Numbers of total peers.", nil, nil), prometheus.GaugeValue}, //int

		logger: logger,
	}, nil
}

func runChronyCheck(address string, log log.Logger) (*NTPCheckResultE, error) {
	//var chronyClient *chrony.Client
	var ch *checker.ChronyCheck
	var err error
	var conn net.Conn

	timeout := 5 * time.Second
	deadline := time.Now().Add(timeout)

	if address == "" {
		return nil, errors.New("address cannot be empty")
	}
	if strings.HasPrefix(address, "/") {
		errors.New("Connection through the socket is not supported (support is off since 0.0.6 due to unresolved issue)")
		//addr, err := net.ResolveUnixAddr("unix", address)
		//if err != nil {
		//	return nil, err
		//}
		//conn, err = net.DialUnix("unix", nil, addr)
		//if err != nil {
		//	return nil, err
		//}
		//level.Debug(log).Log("msg", "unix socket connection mode is used", "address", address)
	} else {
		addr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return nil, err
		}
		conn, err = net.DialUDP("udp", nil, addr)
		if err != nil {
			return nil, err
		}
		level.Debug(log).Log("msg", "udp connection mode is used", "address", address)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}

	ch = checker.NewChronyCheck(conn)

	checkResult, err := ch.Run()
	if err != nil {
		return nil, err
	}
	// dirty conversion from NTPCheckResult to NTPCheckResultE (with additional SourcesStats fields)
	//checkResultE := (*NTPCheckResultE)(unsafe.Pointer(checkResult))
	checkResultE := &NTPCheckResultE{}
	err = deepcopier.Copy(checkResult).To(checkResultE)
	if err != nil {
		errors.New("can't make a deepcopy of checkResult")
	}
	checkResultE.Peers = make(map[uint16]*PeerE)

	for pid := range checkResult.Peers {
		peerInfo := &PeerE{}
		err = deepcopier.Copy(checkResult.Peers[pid]).To(peerInfo)
		if err != nil {
			errors.New("can't make a deepcopy of peerInfo")
		}
		checkResultE.Peers[pid] = peerInfo

		sourceStatsReq := chrony.NewSourceStatsPacket(int32(pid))
		response, err := ch.Client.Communicate(sourceStatsReq)
		if err != nil {
			return nil, errors.Wrap(err, "error during sourceStats request")
		}
		sourceStats, ok := response.(*chrony.ReplySourceStats)
		if !ok {
			return nil, errors.Wrap(err, "cannot cast response into ReplySourceStats")
		}
		logrus.Debugf("%#v", sourceStats)
		// sets new fields as per queried sourceStats
		peerInfo.NSamples = sourceStats.NSamples
		peerInfo.NRuns = sourceStats.NRuns
		peerInfo.SpanSeconds = sourceStats.SpanSeconds
		peerInfo.StdDev = sourceStats.StandardDeviation
		peerInfo.ResidFreq = sourceStats.ResidFreqPPM
		peerInfo.SkewFreq = sourceStats.SkewPPM
		peerInfo.EstOffset = sourceStats.EstimatedOffset
		peerInfo.EstOffsetError = sourceStats.EstimatedOffsetErr
	}

	return checkResultE, nil
}

func (c *chronyCollector) Update(ch chan<- prometheus.Metric) error {
	var b2i = map[bool]float64{false: 0, true: 1}

	resp, err := runChronyCheck(*chronyAddress, c.logger)
	// error handling
	if err != nil {
		level.Error(c.logger).Log("msg", "request to chronyd failed", "err", err)
		return ErrNoData
	}

	// response logging if needed
	if *chronyLogResponseJSON {
		j, err := json.Marshal(resp)
		if err == nil {
			level.Debug(c.logger).Log("msg", j)
		}
	}

	// tracking value subset
	ch <- c.trackingLI.mustNewConstMetric(float64(resp.LI), resp.LIDesc)
	ch <- c.trackingClockSource.mustNewConstMetric(1, resp.ClockSource)
	ch <- c.trackingCorrection.mustNewConstMetric(resp.Correction)
	ch <- c.trackingStratum.mustNewConstMetric(float64(resp.SysVars.Stratum))
	ch <- c.trackingPrecision.mustNewConstMetric(float64(resp.SysVars.Precision))
	ch <- c.trackingRootDelay.mustNewConstMetric(resp.SysVars.RootDelay / 1e3) //initially in ms, see: https://github.com/facebookincubator/ntp/blob/143e098237b0161198f3057998fdf8773c42d612/ntpcheck/checker/system.go#L66
	ch <- c.trackingRootDisp.mustNewConstMetric(resp.SysVars.RootDisp / 1e3)
	ch <- c.trackingOffset.mustNewConstMetric(resp.SysVars.Offset / 1e3)
	ch <- c.trackingFrequency.mustNewConstMetric(resp.SysVars.Frequency)

	// refid parsing (hex as float)
	refID, err := strconv.ParseInt(resp.SysVars.RefID, 16, 64)
	if err == nil {
		ch <- c.trackingRefID.mustNewConstMetric(float64(refID))
	}

	// refTime parsing (str as float)
	t, _ := time.Parse("2006-01-02 15:04:05.99 -0700 MST", resp.SysVars.RefTime)
	if t.Unix() > 0 {
		// Go Zero is   0001-01-01 00:00:00 UTC
		// NTP Zero is  1900-01-01 00:00:00 UTC
		// UNIX Zero is 1970-01-01 00:00:00 UTC
		// so let's keep ALL ancient `reftime` values as zero
		ch <- c.trackingRefTime.mustNewConstMetric(float64(t.UnixNano()) / 1e9)
	} else {
		ch <- c.trackingRefTime.mustNewConstMetric(0)
	}

	// peers value subset
	for _, peer := range resp.Peers {
		peerLabelValues := []string{peer.SRCAdr} //peer address appears as SRCAdr

		//floats
		ch <- c.sourcesPeerOffset.mustNewConstMetric(peer.Offset/1e3, peerLabelValues...) //initially in ms, see: https://github.com/facebookincubator/ntp/blob/81cb02c05f82f8c9cdf32e16f4ee02a3b05bfaf1/ntpcheck/checker/peer.go#L196
		//ch <- c.sourcesPeerDelay.mustNewConstMetric(peer.Delay/1e3, peerLabelValues...)
		//ch <- c.sourcesPeerDispersion.mustNewConstMetric(peer.Dispersion/1e3, peerLabelValues...)
		ch <- c.sourcesPeerJitter.mustNewConstMetric(peer.Jitter/1e3, peerLabelValues...)
		ch <- c.sourcesPeerRootDelay.mustNewConstMetric(peer.RootDelay/1e3, peerLabelValues...)
		ch <- c.sourcesPeerRootDisp.mustNewConstMetric(peer.RootDisp/1e3, peerLabelValues...)
		//source stats
		ch <- c.sourceStatsStdDev.mustNewConstMetric(peer.StdDev, peerLabelValues...)
		ch <- c.sourceStatsEstOffset.mustNewConstMetric(peer.EstOffset, peerLabelValues...)
		ch <- c.sourceStatsEstOffsetError.mustNewConstMetric(peer.EstOffsetError, peerLabelValues...)
		ch <- c.sourceStatsResidFreq.mustNewConstMetric(peer.ResidFreq, peerLabelValues...)
		ch <- c.sourceStatsSkewFreq.mustNewConstMetric(peer.SkewFreq, peerLabelValues...)

		//booleans
		ch <- c.sourcesPeerConfigured.mustNewConstMetric(b2i[peer.Configured], peerLabelValues...)
		ch <- c.sourcesPeerAuthPossible.mustNewConstMetric(b2i[peer.AuthPossible], peerLabelValues...)
		ch <- c.sourcesPeerAuthentic.mustNewConstMetric(b2i[peer.Authentic], peerLabelValues...)
		ch <- c.sourcesPeerReachable.mustNewConstMetric(b2i[peer.Reachable], peerLabelValues...)
		ch <- c.sourcesPeerBroadcast.mustNewConstMetric(b2i[peer.Broadcast], peerLabelValues...)

		//integers
		ch <- c.sourcesPeerSelection.mustNewConstMetric(float64(peer.Selection), append(peerLabelValues, peer.Condition)...)
		ch <- c.sourcesPeerLeap.mustNewConstMetric(float64(peer.Leap), peerLabelValues...)
		ch <- c.sourcesPeerStratum.mustNewConstMetric(float64(peer.Stratum), peerLabelValues...)
		ch <- c.sourcesPeerPrecision.mustNewConstMetric(float64(peer.Precision), peerLabelValues...)
		ch <- c.sourcesPeerReach.mustNewConstMetric(float64(peer.Reach), peerLabelValues...)
		ch <- c.sourcesPeerUnreach.mustNewConstMetric(float64(peer.Unreach), peerLabelValues...)
		ch <- c.sourcesPeerHMode.mustNewConstMetric(float64(peer.HMode), peerLabelValues...)
		ch <- c.sourcesPeerPMode.mustNewConstMetric(float64(peer.PMode), peerLabelValues...)
		ch <- c.sourcesPeerHPoll.mustNewConstMetric(float64(peer.HPoll), peerLabelValues...)
		ch <- c.sourcesPeerPPoll.mustNewConstMetric(float64(peer.PPoll), peerLabelValues...)
		ch <- c.sourcesPeerHeadway.mustNewConstMetric(float64(peer.Headway), peerLabelValues...)
		ch <- c.sourcesPeerXleave.mustNewConstMetric(peer.Xleave, peerLabelValues...)
		//source stats
		ch <- c.sourceStatsNSamples.mustNewConstMetric(float64(peer.NSamples), peerLabelValues...)
		ch <- c.sourceStatsNRuns.mustNewConstMetric(float64(peer.NRuns), peerLabelValues...)
		ch <- c.sourceStatsSpanSeconds.mustNewConstMetric(float64(peer.SpanSeconds), peerLabelValues...)

		// refid parsing (hex as float)
		refID, err := strconv.ParseInt(peer.RefID, 16, 64)
		if err == nil {
			ch <- c.sourcesPeerRefID.mustNewConstMetric(float64(refID), peerLabelValues...)
		}

		// refTime parsing (str as float)
		t, _ := time.Parse("2006-01-02 15:04:05.99 -0700 MST", peer.RefTime)
		if t.Unix() > 0 {
			ch <- c.sourcesPeerRefTime.mustNewConstMetric(float64(t.UnixNano())/1e9, peerLabelValues...)
		} else {
			ch <- c.sourcesPeerRefTime.mustNewConstMetric(0, peerLabelValues...)
		}
	}

	//manually added metrics
	ch <- c.sourcesPeerCount.mustNewConstMetric(float64(len(resp.Peers)))

	return nil
}