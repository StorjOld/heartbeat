#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of Heartbeat: https://github.com/Storj/heartbeat
#
# The MIT License (MIT)
#
# Copyright (c) 2014 Paul Durivage <pauldurivage+git@gmail.com> for Storj Labs
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
from heartbeat import Merkle

from GenericCorrectnessTests import GenericCorrectnessTests
   
class TestMerkleHelper(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass
        
    def test_get_next_seed(self):
        seed = os.urandom(32)
        key = os.urandom(32)
        self.assertEqual(Merkle.MerkleHelper.get_next_seed(key,seed),Merkle.MerkleHelper.get_next_seed(key,seed))
        
    def test_get_file_hash(self):
        seed = os.urandom(32)
        key = os.urandom(32)
        for i in range(0,10):
            seed = Merkle.MerkleHelper.get_next_seed(key,seed)
            with open('files/test.txt','rb') as file:
                hash = Merkle.MerkleHelper.get_file_hash(file,seed)
            with open('files/test2.txt','rb') as file:
                hash2 = Merkle.MerkleHelper.get_file_hash(file,seed)
            self.assertEqual(hash,hash2)
        
    def test_get_chunk_hash(self):
        seed = os.urandom(32)
        key = os.urandom(32)
        for i in range(0,100):
            seed = Merkle.MerkleHelper.get_next_seed(key,seed)
            with open('files/test.txt','rb') as file:
                hash = Merkle.MerkleHelper.get_chunk_hash(file,seed)
            with open('files/test2.txt','rb') as file:
                hash2 = Merkle.MerkleHelper.get_chunk_hash(file,seed)
            self.assertEqual(hash,hash2)


class TestCorrectness(unittest.TestCase):
    def test_correctness(self):
        GenericCorrectnessTests.generic_correctness_test(self,Merkle.Merkle)
    def test_scheme(self):
        GenericCorrectnessTests.generic_scheme_test(self,Merkle.Merkle)
        
        
if __name__ == '__main__':
    unittest.main()
