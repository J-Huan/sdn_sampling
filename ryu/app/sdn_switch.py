# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import HANDSHAKE_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib import pcaplib
from ryu import utils
from ryu.lib import hub

class SDNSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    MISS_SEND_LENGTH = 1500  # set to match maximum ethernet payload
    DEFAULT_TABLE = 0
    GROUP_ID = 1
    PRIORITY = 50

    def __init__(self, *args, **kwargs):
        super(SDNSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.group_enabled = False
        self.sampling_enabled = True
        self.pcap_writer = pcaplib.Writer(open('result.pcap', 'wb'))
        self.sample_size = 200.0  # sample size in ms  - ST (0.1s) ; LP (0.1s); MuST (0.2s)
        self.interval_between_samples = 300.0  # interval between samples in ms - ST (0.5s) ; LP (0.2s); MuST (0.3s)
        self.N = 3  # LP (2); MuST (3)
        self.min_interval_between_samples = 100.0  # LP (0.2s); MuST (0.1s)
        self.max_interval_between_samples = 8000.0  # LP (10s); MuST (8s)
        self.sampling_options = {0: self.systematic_time_based,
                                 1: self.linear_prediction,
                                 2: self.must}
        self.sampling_technique = 2  # sampling technique selection
        self.min_sample_size = 100.0
        self.max_sample_size = 2000.0
        self.m_min = 0.9
        self.m_max = 1.1
        self.nr_packet_in_sampling = 0
        self.nr_packet_in_total = 0
        self.throughput = 0
        self.trial_counter = 0
        self.m_factor = 1.0
        self.nr_samples = 0
        self.k = 0.15
        self.logfile = open('logfile.txt','wb')

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.debug('OFPErrorMsg received: type=0x%02x code=0x%02x '
                          'message=%s', msg.type, msg.code,
                          utils.hex_array(msg.data))

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapath = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

        # Configure datapath with custom MISS_SEND_LENGTH
        self.send_set_config(datapath)

        self.add_flow(datapath, 0, 0, match, actions, table_id=self.DEFAULT_TABLE)


    def add_flow(self, datapath, hard_timeout, priority, match, actions, table_id=None, buffer_id=None):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = ofp_parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,table_id=table_id,
                                        priority=priority, hard_timeout=hard_timeout,
                                        match=match, instructions=inst,
                                        flags=ofp.OFPFF_SEND_FLOW_REM)

        else:
            mod = ofp_parser.OFPFlowMod(datapath=datapath, table_id=table_id,
                                        priority=priority, hard_timeout=hard_timeout,
                                        match=match, instructions=inst,
                                        flags=ofp.OFPFF_SEND_FLOW_REM)

        datapath.send_msg(mod)

    def del_flow(self, datapath, priority, match, instructions, table_id):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        mod=ofp_parser.OFPFlowMod(datapath, 0, 0,
                                  table_id,ofp.OFPFC_DELETE,0, 0,
                                  priority,ofp.OFPCML_NO_BUFFER,ofp.OFPP_ANY,
                                  ofp.OFPG_ANY, 0,match, instructions)
        datapath.send_msg(mod)

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                   buffer_id=buffer_id,
                                                   data=msg_data, in_port=src_port,
                                                   actions=actions)
        return out

    def send_packet_out(self, datapath, buffer_id, data, src_port, dst_port=None):
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)

    def flood(self, msg):
        datapath = msg.datapath
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        out = self._build_packet_out(datapath, ofp.OFP_NO_BUFFER,
                                     ofp.OFPP_CONTROLLER,
                                     ofp.OFPP_FLOOD, msg.data)

        datapath.send_msg(out)
        self.logger.debug("Flooding packet")

    def send_group_mod(self, datapath, group_id, action):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        watch_port = ofproto_v1_3.OFPP_ANY
        watch_group = ofproto_v1_3.OFPQ_ALL

        normal_actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL, 0)]
        sampling_actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]

        if action == 'add':
            buckets = [ofp_parser.OFPBucket(watch_port=watch_port, watch_group=watch_group, actions=normal_actions),
                       ofp_parser.OFPBucket(watch_port=watch_port, watch_group=watch_group, actions=sampling_actions)]

            req = ofp_parser.OFPGroupMod(datapath=datapath,
                                         command=ofp.OFPFC_ADD,
                                         type_=ofp.OFPGT_ALL,
                                         group_id=group_id,
                                         buckets=buckets)

        if action == 'delete':
            req = ofp_parser.OFPGroupMod(datapath=datapath,
                                         command=ofp.OFPFC_DELETE,
                                         type_=ofp.OFPGT_ALL,
                                         group_id=group_id)

        if action == 'sampling_on':

            buckets = [ofp_parser.OFPBucket(watch_port=watch_port, watch_group=watch_group, actions=normal_actions),
                       ofp_parser.OFPBucket(watch_port=watch_port, watch_group=watch_group, actions=sampling_actions)]

            req = ofp_parser.OFPGroupMod(datapath=datapath,
                                         command=ofp.OFPFC_MODIFY,
                                         type_=ofp.OFPGT_ALL,
                                         group_id=group_id,
                                         buckets=buckets)

        if action == 'sampling_off':
            buckets = [ofp_parser.OFPBucket(watch_port=watch_port, watch_group=watch_group, actions=normal_actions)]

            req = ofp_parser.OFPGroupMod(datapath=datapath,
                                         command=ofp.OFPFC_MODIFY,
                                         type_=ofp.OFPGT_ALL,
                                         group_id=group_id,
                                         buckets=buckets)
        
        datapath.send_msg(req)

    def send_get_config_request(self, datapath):
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPGetConfigRequest(datapath)
        datapath.send_msg(req)

    def send_set_config(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPSetConfig(datapath, ofp.OFPC_FRAG_NORMAL, self.MISS_SEND_LENGTH)
        datapath.send_msg(req)
        
    def send_port_desc_stats_request(self, datapath):
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        ofproto = msg.datapath.ofproto
        reason = msg.reason

        if msg.msg_len < msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)

        self.nr_packet_in_total += 1

        if self.sampling_enabled:
            self.pcap_writer.write_pkt(msg.data)
            self.throughput_tmp = self.throughput
            self.throughput += msg.msg_len
            self.nr_packet_in_sampling += 1

        if reason != ofproto.OFPR_ACTION:

            datapath = msg.datapath
            ofp_parser = datapath.ofproto_parser

            in_port = msg.match['in_port']
            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocols(ethernet.ethernet)[0]
            dst = eth.dst
            src = eth.src
            dpid = datapath.id
            self.mac_to_port.setdefault(dpid, {})

            self.logger.debug('packet in %s %s %s %s %s', dpid, src, dst, in_port, reason)
            self.logger.debug('OFPPacketIn received: '
                              'buffer_id=%x total_len=%d'
                              'table_id=%d match=%s data=%s',
                              msg.buffer_id, msg.total_len,
                              msg.table_id, msg.match,
                              utils.hex_array(msg.data))

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            if out_port != ofproto.OFPP_FLOOD:
                if self.group_enabled is False:
                    self.send_group_mod(datapath, self.GROUP_ID, 'add')  # inject group into the switch
                    self.logger.debug('Group %s injected', self.GROUP_ID)
                    self.sampling_thread = hub.spawn(self.sampling_options[self.sampling_technique])
                    self.group_enabled = True

                actions = [ofp_parser.OFPActionGroup(group_id=self.GROUP_ID)]
                match = ofp_parser.OFPMatch(in_port=in_port, eth_dst=dst)

                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 0, self.PRIORITY, match, actions, self.DEFAULT_TABLE, msg.buffer_id)
                else:
                    self.add_flow(datapath, 0, self.PRIORITY, match, actions, self.DEFAULT_TABLE)

                self.send_packet_out(datapath, msg.buffer_id, msg.data, in_port)
            else:
                self.flood(msg)  # flood the packet

    @set_ev_cls(ofp_event.EventOFPGetConfigReply, MAIN_DISPATCHER)
    def get_config_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        flags = []

        if msg.flags & ofp.OFPC_FRAG_NORMAL:
            flags.append('NORMAL')
        if msg.flags & ofp.OFPC_FRAG_DROP:
            flags.append('DROP')
        if msg.flags & ofp.OFPC_FRAG_REASM:
            flags.append('REASM')
        self.logger.debug('OFPGetConfigReply received: '
                          'flags=%s miss_send_len=%d',
                          ','.join(flags), msg.miss_send_len)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'

        field = []
        for f in msg.match.fields:
            field.append('%s: value=%s' % (f.__class__.__name__, f.value))

        self.logger.debug('OFPFlowRemoved received: '
                          'cookie=%d priority=%d reason=%s table_id=%d '
                          'duration_sec=%d duration_nsec=%d '
                          'idle_timeout=%d hard_timeout=%d '
                          'packet_count=%d byte_count=%d match.fields=%s',
                          msg.cookie, msg.priority, reason, msg.table_id,
                          msg.duration_sec, msg.duration_nsec,
                          msg.idle_timeout, msg.hard_timeout,
                          msg.packet_count, msg.byte_count, field)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPPR_ADD:
            reason = 'ADD'
        elif msg.reason == ofp.OFPPR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPPR_MODIFY:
            reason = 'MODIFY'
        else:
            reason = 'unknown'
            self.logger.debug('OFPPortStatus received: reason=%s desc=%s', reason, msg.desc)

    ### Sampling related methods

    def new_sample(self, sample_size):

        # enable sampling
        for dp in self.datapaths.values():
            self.send_group_mod(dp, self.GROUP_ID, 'sampling_on')
        self.sampling_enabled = True

        hub.sleep(sample_size / 1000.0)
        self.nr_samples += 1

    def new_sampling_interval(self, interval_between_samples):

        # disable sampling
        for dp in self.datapaths.values():
            self.send_group_mod(dp, self.GROUP_ID, 'sampling_off')
        self.sampling_enabled = False

        hub.sleep(interval_between_samples / 1000.0)

    def predictor(self, vector_x, vector_t):
        i = 1
        n = self.N
        sum = 0.0

        while i < n:
            sum += abs((vector_x[i] - vector_x[i - 1]) / vector_t[i - 1])
            i += 1

        forecast = vector_x[n - 1] + (vector_t[n - 1] / (n - 1) * sum)
        return forecast

    def systematic_time_based(self):
        sample_size = self.sample_size
        interval_between_samples = self.interval_between_samples

        while 1:
            throughput_before = self.throughput
            self.new_sample(sample_size)
            throughput_after = self.throughput
            self.new_sampling_interval(interval_between_samples)

            if throughput_before == throughput_after:
                self.log_sampling()

    def linear_prediction(self):
        i = 0
        n = self.N
        vector_x = [0] * n
        vector_t = [0] * n
        sample_size = self.sample_size
        interval_between_samples = self.interval_between_samples
        while i < n:
            throughput_before = self.throughput
            self.new_sample(sample_size)
            throughput_after = self.throughput
            vector_x[i] = throughput_after - throughput_before
            vector_t[i] = interval_between_samples * 0.001
            i += 1
            self.new_sampling_interval(interval_between_samples)

        while 1:
            xp = self.predictor(vector_x,vector_t)
            throughput_before = self.throughput
            self.new_sample(sample_size)
            throughput_after = self.throughput
            s = throughput_after - throughput_before

            m_factor = 1.0
            if s - vector_x[n - 1] != 0:
                m_factor = abs((xp - vector_x[n - 1]) / (s - vector_x[n - 1]))
                m_factor = round(m_factor, 2)
            else:
                interval_between_samples *= 2

            if m_factor < self.m_min:
                interval_between_samples *= m_factor

            elif m_factor > self.m_max:
                interval_between_samples += 1000.0

            if interval_between_samples < self.min_interval_between_samples:
                interval_between_samples = self.min_interval_between_samples
            elif interval_between_samples > self.max_interval_between_samples:
                interval_between_samples = self.max_interval_between_samples

            i = 0
            j = 1
            while j < n:
                vector_x[i] = vector_x[j]
                vector_t[i] = vector_t[j]
                i += 1
                j += 1
            vector_x[i] = s
            vector_t[i] = interval_between_samples * 0.001

            self.interval_between_samples = interval_between_samples
            self.m_factor = m_factor

            self.new_sampling_interval(interval_between_samples)

            if throughput_before == throughput_after:
                self.log_sampling()

    def must(self):
        i = 0
        n = self.N
        vector_x = [0] * n
        vector_t = [0] * n
        sample_size = self.sample_size
        interval_between_samples = self.interval_between_samples

        while i < n:
            throughput_before = self.throughput
            self.new_sample(sample_size)
            throughput_after = self.throughput
            vector_x[i] = throughput_after - throughput_before
            vector_t[i] = interval_between_samples * 0.001
            i += 1

            self.new_sampling_interval(interval_between_samples)

        while 1:
            xp = self.predictor(vector_x,vector_t)
            throughput_before = self.throughput
            self.new_sample(sample_size)
            throughput_after = self.throughput
            s = throughput_after - throughput_before

            m_factor = 1.0
            if s:
                m_factor = xp / s
                m_factor = round(m_factor, 2)

            if m_factor < self.m_min:
                interval_between_samples *= m_factor
                sample_size *= m_factor

            elif m_factor > self.m_max:
                interval_between_samples *= 2
                sample_size *= (1 + self.k)

            if interval_between_samples < self.min_interval_between_samples:
                interval_between_samples = self.min_interval_between_samples
            elif interval_between_samples > self.max_interval_between_samples:
                interval_between_samples = self.max_interval_between_samples

            if sample_size < self.min_sample_size:
                sample_size = self.min_sample_size
            elif sample_size > self.max_sample_size:
                sample_size = self.max_sample_size

            if s:
                i = 0
                j = 1
                while j < n:
                    vector_x[i] = vector_x[j]
                    vector_t[i] = vector_t[j]
                    i += 1
                    j += 1
                vector_x[i] = s
                vector_t[i] = interval_between_samples * 0.001

            self.interval_between_samples = round(interval_between_samples,0)
            self.sample_size = round(sample_size,0)
            self.m_factor = m_factor

            self.new_sampling_interval(interval_between_samples)

            if throughput_before == throughput_after:
                self.log_sampling()

    def log_sampling(self):
        if self.sampling_technique == 0:
            print >> self.logfile, self.nr_samples, self.nr_packet_in_sampling, \
                self.nr_packet_in_total, self.sample_size, \
                self.interval_between_samples, self.throughput

            self.logger.debug('nr_samples: %d\n'
                              'nr_packet_in_sampling: %d, nr_packet_in_total: %d\n'
                              'sample_size: %.2f,  interval_between_samples: %.2f\n'
                              'throughput: %d\n',
                              self.nr_samples,
                              self.nr_packet_in_sampling, self.nr_packet_in_total,
                              self.sample_size, self.interval_between_samples,
                              self.throughput)

        else:
            print >> self.logfile, self.m_factor, self.nr_samples, self.nr_packet_in_sampling, \
                self.nr_packet_in_total, self.sample_size, \
                self.interval_between_samples, self.throughput

            self.logger.debug('nr_samples: %d, m_factor: %.2f \n'
                              'nr_packet_in_sampling: %d, nr_packet_in_total: %d\n'
                              'sample_size: %.2f,  interval_between_samples: %.2f\n'
                              'throughput: %d\n',
                              self.nr_samples, self.m_factor,
                              self.nr_packet_in_sampling, self.nr_packet_in_total,
                              self.sample_size, self.interval_between_samples,
                              self.throughput)