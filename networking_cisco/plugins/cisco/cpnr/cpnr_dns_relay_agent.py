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


import eventlet
import os
import struct

from neutron.common import config
from oslo_log import log as logging

from networking_cisco.plugins.cisco.cpnr import netns

LOG = logging.getLogger(__name__)

RLIMIT_NOFILE_LIMIT = 16384


class DnsPacket(object):

    # Byte array representation of common TXT RR fields that will be inserted
    # in each request
    #    Format is:
    #       - domain name ("10_cpnr_info5cisco3com0")
    #       - rr type (2 bytes, value = 16)
    #       - class (2 bytes, value = 1)
    #       - ttl (4 bytes, value = 0)
    TXT_RR = bytearray(b'\x0a\x5f\x63\x70\x6e\x72\x5f\x69\x6e\x66\x6f\x05'
                       b'\x63\x69\x73\x63\x6f\x03\x63\x6f\x6d\x00\x00\x10'
                       b'\x00\x01\x00\x00\x00\x00')

    QUERY_TYPE_AND_CLASS = 4
    TYPE_CLASS_AND_TTL_LENGTH = 8
    OPTIONAL_RR = 41
    COUNTS_LENGTH = 8  # Question, Answer, Authority and Additional RR Count.
    IDENTIFIER_FLAGS_AND_CODES_LENGTH = 4

    def __init__(self):
        self.buf = ''
        self.msgid = ''
        self.isreq = False
        self.viewid = ""
        self.arcnt = 0
        self.txt_insert_pos = -1
        self.optlen = 0

    @classmethod
    def parse(cls, buf, buflen):
        pkt = DnsPacket()

        # parse out the header
        (pkt.msgid,) = cls.struct('!H').unpack_from(buf, 0)
        (info,) = cls.struct('B').unpack_from(buf, 2)
        pos = DnsPacket.IDENTIFIER_FLAGS_AND_CODES_LENGTH

        # check if query
        isquery = not (info & 0x80)
        if not isquery:
            pkt.buf = buf
            LOG.debug("DNS packet is a response")
            return pkt

        LOG.debug("DNS packet is a query")
        pkt.isreq = True

        (qdcnt,) = cls.struct('!H').unpack_from(buf, 4)
        (ancnt,) = cls.struct('!H').unpack_from(buf, 6)
        (nscnt,) = cls.struct('!H').unpack_from(buf, 8)
        (arcnt,) = cls.struct('!H').unpack_from(buf, 10)
        pkt.arcnt = arcnt
        pos += DnsPacket.COUNTS_LENGTH

        LOG.debug('Parsed pkt: msgid %s qdcnt %i ancnt %i nscnt %i '
                  'arcnt %i', pkt.msgid, qdcnt, ancnt, nscnt, arcnt)

        for i in range(qdcnt):
            pos = cls.skip_over_domain_name(buf, pos)
            pos += DnsPacket.QUERY_TYPE_AND_CLASS

        if ancnt != 0 or nscnt != 0:
            # unexpected, log and return packet
            LOG.debug('Unexpected answers in query, ancnt %i nscnt %i',
                      ancnt, nscnt)
            pkt.buf = buf
            return pkt

        # walk through additional section, check for OPT RR (if present, must
        # come last)
        tmp_pos = pos
        for i in range(arcnt):
            tmp_pos = cls.skip_over_domain_name(buf, tmp_pos)
            (type,) = cls.struct('!H').unpack_from(buf, tmp_pos)
            tmp_pos += DnsPacket.TYPE_CLASS_AND_TTL_LENGTH
            (rdlen,) = cls.struct('!H').unpack_from(buf, tmp_pos)
            tmp_pos += 2 + rdlen  # rdlength and rdata

            if type == DnsPacket.OPTIONAL_RR:
                pkt.optlen = buflen - pos
                break
            else:
                pos = tmp_pos
        pkt.txt_insert_pos = pos
        pkt.buf = buf
        return pkt

    def get_msgid(self):
        return self.msgid

    def set_viewid(self, id):
        self.viewid = id

    def data(self):
        if not self.isreq or not self.viewid:
            return self.buf

        # make a copy of OPT RR, if present
        opt_data = ''
        if self.optlen != 0:
            opt_data = self.buf[self.txt_insert_pos:self.txt_insert_pos +
                                self.optlen]

        # insert TXT RR and data into buf
        pos = self.txt_insert_pos
        self.buf[pos:pos + len(DnsPacket.TXT_RR)] = DnsPacket.TXT_RR
        pos += len(DnsPacket.TXT_RR)
        txt_str = 'view: %s' % (self.viewid,)
        self.struct('!HB%is' %
                    (len(txt_str),)).pack_into(self.buf, pos,
                                               len(txt_str) + 1,
                                               len(txt_str),
                                               txt_str.encode('utf-8'))

        pos += 3 + len(txt_str)

        # bump up arcnt
        self.arcnt += 1
        self.struct('!H').pack_into(self.buf, 10, self.arcnt)

        # copy OPT RR back in at end if presesnt
        if opt_data:
            self.buf[pos:pos + len(opt_data)] = opt_data
            pos += len(opt_data)

        return self.buf[:pos]

    @classmethod
    def skip_over_domain_name(cls, buf, pos):
        tmplen = -1
        while tmplen != 0:
            (tmplen,) = cls.struct('B').unpack_from(buf, pos)
            if (tmplen & 0x80) and (tmplen & 0x40):
                pos += 2  # length and pointer, comes last
                break
            else:
                pos += 1 + tmplen
        return pos

    structcache = {}

    @classmethod
    def struct(cls, fmt):
        return cls.structcache.setdefault(fmt, struct.Struct(fmt))


def main():
    try:
        netns.increase_ulimit(RLIMIT_NOFILE_LIMIT)
    except Exception:
        LOG.error('Failed to increase ulimit for DNS relay')
    if os.getuid() != 0:
        config.setup_logging()
        LOG.error('Must run dns relay as root')
        return
    eventlet.monkey_patch()
    config.setup_logging()


if __name__ == "__main__":
    main()
