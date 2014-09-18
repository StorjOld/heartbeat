#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of Heartbeat: https://github.com/Storj/heartbeat
#
# The MIT License (MIT)
#
# Copyright (c) 2014 Paul Durivage <pauldurivage+git@gmail.com> for Storj Labs
# Copyright (c) 2014 Will James <jameswt@gmail.com> for Storj Labs
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import io
import os
import sys
import random
import hashlib
import unittest
from decimal import Decimal
import pickle

from heartbeat.exc import HeartbeatError
from heartbeat import PySwPriv

from GenericCorrectnessTests import GenericCorrectnessTests

class TestKeyedPRF(unittest.TestCase):
    def test_pad(self):
        data0 = b"test data 0"
        pdata0 = PySwPriv.KeyedPRF.pad(data0,15)
        self.assertEqual(data0+b"\0\0\0\0",pdata0)
        
        pdata0 = PySwPriv.KeyedPRF.pad(data0,7)
        self.assertEqual(data0[0:7],pdata0)
        
    def test_consistency(self):
        k = os.urandom(32)
        f1 = PySwPriv.KeyedPRF(k,10000)
        f2 = PySwPriv.KeyedPRF(k,10000)
        for i in range(0,100):
            self.assertEqual(f1.eval(i),f2.eval(i))
    
class TestCorrectness(unittest.TestCase):
    def test_correctness(self):
        GenericCorrectnessTests.generic_correctness_test(self,PySwPriv.PySwPriv)
    def test_scheme(self):
        GenericCorrectnessTests.generic_scheme_test(self,PySwPriv.PySwPriv)
        
        
if __name__ == '__main__':
    unittest.main()
