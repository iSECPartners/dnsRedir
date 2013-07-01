#!/usr/bin/env python
"""
"""

from dnsRedir import *

def test() :
    def t(s) :
        xs = parseIPv6(s)
        print s, map(ord, xs), mkIPv6(xs)
    t('::1')
    t('ffff::')
    t('::10.200.200.1')
    t('::ffff:127.0.0.1')
    t('1111::2222:3333')

test()
