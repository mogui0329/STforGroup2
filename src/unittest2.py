import unittest
from ctypes import *
from template import *

# This is used to test `tcp.h` and `tcp.c`.
# Author: zhsh.

import unittest
import os
from tcp import *

class TestTCP(unittest.TestCase):
    def test_trace_tcp_connect(self):
        # Create some test data
        ctx = {'r9': 0, 'r8': 0, 'rdi': 0, 'rsi': 0, 'rdx': 0, 'rcx': 0, 'rax': 0}
        skp = {'__sk_common': {'skc_family': 2},
               '__sk_common.skc_daddr': 0x0a000002,
               '__sk_common.skc_rcv_saddr': 0x0a000001}
        data = b"\\\\x45\\\\x00\\\\x00\\\\x28\\\\x00\\\\x01\\\\x00\\\\x00\\\\x40\\\\x06\\\\x00\\\\x00\\\\x0a\\\\x00\\\\x00\\\\x01\\\\x0a\\\\x00\\\\x00\\\\x02\\\\x14\\\\x00\\\\x14\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00"
        iph = iphdr.from_buffer_copy(data)
        tcph = tcphdr.from_buffer_copy(data[20:])
        expected_event = tcp_conn_event(timestamp_ns=0, saddr=iph.saddr, daddr=iph.daddr, sport=tcph.source, dport=tcph.dest, conn_type=0)

        # Mock the BPF functions
        bpf_ktime_get_ns = lambda: 0
        bpf_perf_event_output = lambda ctx, map, flags, data, size: self.assertEqual(data, expected_event)

        # Call the function being tested
        trace_tcp_connect(ctx, skp)

if __name__ == '__main__':
    unittest.main()
