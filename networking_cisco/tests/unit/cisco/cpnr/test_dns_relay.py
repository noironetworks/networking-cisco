# Copyright 2016 Cisco Systems, Inc.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

from binascii import hexlify
import unittest

from networking_cisco.plugins.cisco.cpnr.cpnr_dns_relay_agent import DnsPacket


class TestDnsPacket(unittest.TestCase):

    def test_parse(self):
        # test regular DNS request
        line = ('84 a5 01 00 00 01 00 00 00 00 00 00 06 72 '
               '65 64 68 61 74 03 63 6f 6d 00 00 01 00 01')
        buf = bytearray.fromhex(line)
        pkt = DnsPacket.parse(buf, 28)
        self.assertEqual(0x84a5, pkt.get_msgid())
        self.assertTrue(pkt.isreq)
        self.assertEqual(0, pkt.arcnt)
        self.assertEqual(0, pkt.optlen)
        self.assertEqual(28, pkt.txt_insert_pos)

        # test DNS request with EDNS0
        line = ('81 71 01 20 00 01 00 00 00 00 00 01 06 72 65 '
                '64 68 61 74 03 63 6f 6d 00 00 01 00 01 00 00 '
                '29 10 00 00 00 00 00 00 00')
        buf = bytearray.fromhex(line)
        pkt = DnsPacket.parse(buf, 38)
        self.assertEqual(0x8171, pkt.get_msgid())
        self.assertTrue(pkt.isreq)
        self.assertEqual(1, pkt.arcnt)
        self.assertEqual(10, pkt.optlen)
        self.assertEqual(28, pkt.txt_insert_pos)

        # test regular DNS response
        line = ('b6 5e 81 80 00 01 00 01 00 00 00 00 06 72 65 '
                '64 68 61 74 03 63 6f 6d 00 00 01 00 01 c0 0c '
                '00 01 00 01 00 00 00 08 00 04 d1 84 b7 69')
        buf = bytearray.fromhex(line)
        pkt = DnsPacket.parse(buf, 44)
        self.assertEqual(0xb65e, pkt.get_msgid())
        self.assertFalse(pkt.isreq)
        self.assertEqual(0, pkt.arcnt)
        self.assertEqual(0, pkt.optlen)
        self.assertEqual(-1, pkt.txt_insert_pos)

    def test_set_viewid(self):
        pkt = DnsPacket()
        pkt.set_viewid('123456789')
        self.assertEqual(pkt.viewid, '123456789')

    def test_data(self):
        # call with regular DNS request
        line = ('84 a5 01 00 00 01 00 00 00 00 00 00 06 72 '
               '65 64 68 61 74 03 63 6f 6d 00 00 01 00 01')
        buf = bytearray.fromhex(line)
        pktbuf = bytearray(4096)
        pktbuf[0:len(buf)] = buf
        pkt = DnsPacket.parse(pktbuf, 28)
        pkt.set_viewid('123456')
        mod_buf = pkt.data()
        self.assertEqual(pkt.arcnt, 1)
        hextxtstr = hexlify(DnsPacket.TXT_RR)
        hexstr = hexlify(mod_buf)
        self.assertNotEqual(-1, hexstr.find(hextxtstr))

        # call with DNS request with EDNS0
        line = ('81 71 01 20 00 01 00 00 00 00 00 01 06 72 65 '
                '64 68 61 74 03 63 6f 6d 00 00 01 00 01 00 00 '
                '29 10 00 00 00 00 00 00 00')
        buf = bytearray.fromhex(line)
        pktbuf = bytearray(4096)
        pktbuf[0:len(buf)] = buf
        pkt = DnsPacket.parse(pktbuf, 38)
        pkt.set_viewid('123456')
        mod_buf = pkt.data()
        self.assertEqual(2, pkt.arcnt)
        hexstr = hexlify(mod_buf)
        self.assertNotEqual(-1, hexstr.find(hextxtstr))

    def test_skip_over_domain_name(self):
        # test skip over name at beginning, end up on ^
        # 4test5cisco3com0^
        bytes = bytearray(b'\x04\x74\x65\x73\x74\x05\x63\x69\x73\x63'
                          b'\x6f\x03\x63\x6f\x6d\x00\x5e')
        pos = DnsPacket.skip_over_domain_name(bytes, 0)
        self.assertEqual(16, pos)
        self.assertEqual('^', chr(bytes[pos]))

        # test skip over name in the middle, end up on ^
        # 2552552552554test5cisco3com0^
        bytes = bytearray(b'\xff\xff\xff\xff\x04\x74\x65\x73\x74\x05\x63'
                          b'\x69\x73\x63\x6f\x03\x63\x6f\x6d\x00\x5e')
        pos = DnsPacket.skip_over_domain_name(bytes, 4)
        self.assertEqual(20, pos)
        self.assertEqual('^', chr(bytes[pos]))

        # test skip over length and pointer at beginning, end up on ^
        bytes = bytearray(b'\xc0\x55\x5e')
        pos = DnsPacket.skip_over_domain_name(bytes, 0)
        self.assertEqual(2, pos)
        self.assertEqual('^', chr(bytes[pos]))

        # test skip over length and pointer in the middle, end up on ^
        bytes = bytearray(b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xc0\x55\x5e')
        pos = DnsPacket.skip_over_domain_name(bytes, 9)
        self.assertEqual(11, pos)
        self.assertEqual('^', chr(bytes[pos]))
