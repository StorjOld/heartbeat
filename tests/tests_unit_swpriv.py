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
from heartbeat import SwPriv

from GenericCorrectnessTests import GenericCorrectnessTests
   
class TestSubClasses(unittest.TestCase):
    def setUp(self):
        self.challenge1 = SwPriv.Challenge()
        self.challenge2 = SwPriv.Challenge()
        self.tag1 = SwPriv.Tag()
        self.tag2 = SwPriv.Tag()
        self.state1 = SwPriv.State()
        self.state2 = SwPriv.State()
        self.proof1 = SwPriv.Proof()
        self.proof2 = SwPriv.Proof()

    def tearDown(self):
        del self.challenge1
        del self.challenge2
        del self.tag1
        del self.tag2
        del self.state1
        del self.state2
        del self.proof1
        del self.proof2

    def assign_and_compare_states(self, item1, item2):
        state1 = item1.__getstate__()
        item2.__setstate__(state1)
        state2 = item2.__getstate__()
        self.assertEqual(state1,state2)
        
    def test_get_set_state(self):
        self.assign_and_compare_states(self.challenge1, self.challenge2)
        self.assign_and_compare_states(self.tag1, self.tag2)
        self.assign_and_compare_states(self.proof1, self.proof2)
        key = os.urandom(self.state1.keysize())
        self.state1.encrypt(key,key,True)
        state1 = self.state1.__getstate__()
        self.state2.__setstate__(state1)
        self.state2.decrypt(key,key)
        self.state2.encrypt(key,key,True)
        state2 = self.state2.__getstate__()
        self.assertEqual(state1,state2)

class TestSwPriv(unittest.TestCase):
    def test_exceptions(self):
        state = SwPriv.State()
        with self.assertRaises(HeartbeatError) as ex:
            state.__setstate__()
        
        ex_msg = ex.exception.message
        self.assertEqual("__setstate__ only takes one argument: state",ex_msg)
        
        with self.assertRaises(HeartbeatError) as ex:
            state.encrypt()
        
        ex_msg = ex.exception.message
        self.assertEqual("encrypt() takes at least two arguments: the encryption key and the mac key and an optional argument a bool, whether to use convergent encryption",ex_msg)
        
        with self.assertRaises(HeartbeatError) as ex:
            state.decrypt()
            
        ex_msg = ex.exception.message
        self.assertEqual("decrypt() takes two arguments: the encryption key and the mac key.",ex_msg)
        
        with self.assertRaises(HeartbeatError) as ex:
            state.encrypt(None,None)
            
        ex_msg = ex.exception.message
        self.assertEqual("Invalid encryption key.",ex_msg)
        
        key_len = state.keysize()
        
        with self.assertRaises(HeartbeatError) as ex:
            state.encrypt(os.urandom(key_len-1),os.urandom(key_len-1))
            
        ex_msg = ex.exception.message
        self.assertEqual("Encryption key must be "+str(key_len)+" bytes in length.  Use keysize() to retrieve the key size.",ex_msg)
    
    def test_size(self):
        beat = SwPriv.SwPriv()
        
        with open('files/test7.txt','rb') as file:
            file.seek(0,2)
            len_file = file.tell()
        
        with open('files/test7.txt','rb') as file:
            (tag,state) = beat.encode(file)
        
        len_tag = len(tag.__getstate__())
        
        # when encoded in binary the tag will be a tenth the size of the file
        # plus some overhead for storage of the integers.  the overhead should be
        # 4 bytes per 128 byte integer, plus 4 bytes for the number of integers
        self.assertLessEqual(len_tag,len_file*0.104 + 4)
    
class TestCorrectness(unittest.TestCase):
    def test_correctness(self):
        GenericCorrectnessTests.generic_correctness_test(self,SwPriv.SwPriv)
    def test_scheme(self):
        GenericCorrectnessTests.generic_scheme_test(self,SwPriv.SwPriv)
        
        
if __name__ == '__main__':
    unittest.main()
