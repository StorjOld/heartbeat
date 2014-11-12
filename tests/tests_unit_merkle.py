#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of Heartbeat: https://github.com/Storj/heartbeat
#
# The MIT License (MIT)
#
# Copyright (c) 2014 Paul Durivage <pauldurivage+git@gmail.com> for Storj Labs
# Copyright (c) 2014 Will James <jameswt@gmail.com>
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
import pickle
import json


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


class TestMerkleTree(unittest.TestCase):
    def test_build(self):
        leaf_counts = [1, 9, 257]
        for i in leaf_counts:
            mt = Merkle.MerkleTree()
            for j in range(0,i):
                mt.add_leaf(os.urandom(32))
            mt.build()
            # check all the leaves
            for j in range(0,i):
                self.assertTrue(Merkle.MerkleTree.verify_branch(mt.leaves[j],mt.get_branch(j),mt.get_root()))

    def test_invalid_leaf(self):
        self.assertFalse(Merkle.MerkleTree.verify_branch([],[],None))

    def test_get_partner(self):
        for i in range(0,20):
            j = random.randint(0,100)
            p = Merkle.MerkleTree.get_partner(j)
            if (Merkle.MerkleTree.is_left(j)):
                p2 = j+1
            else:
                p2 = j-1
            self.assertEqual(p,p2)
            
    def test_invalid_root(self):
        mt = Merkle.MerkleTree()
        for i in range(0,10):
            mt.add_leaf(os.urandom(32))
        mt.build()
        for i in range(0,10):
            self.assertFalse(Merkle.MerkleTree.verify_branch(mt.leaves[i],mt.get_branch(i),os.urandom(32)))

    def test_serialization(self):
        mt = Merkle.MerkleTree()
        for i in range(0,10):
            mt.add_leaf(os.urandom(32))
        mt.build()
        
        d = mt.todict()
        mt2 = Merkle.MerkleTree.fromdict(d)
        
        self.assertEqual(mt,mt2)
            
class TestMerkle(unittest.TestCase):
    def test_signing(self):
        state = Merkle.State(0,os.urandom(32),256,os.urandom(32))
        key = os.urandom(32)
        state.sign(key)
        state.checksig(key)
        # modify
        state.seed = os.urandom(32)
        with self.assertRaises(HeartbeatError) as ex:
            state.checksig(key)

        ex_msg = ex.exception.message
        self.assertEqual("Signature invalid on state.",ex_msg)

    def test_init(self):
        k = os.urandom(32)
        beat = Merkle.Merkle(key=k)
        self.assertEqual(k,beat.key)

    def test_run_out_of_challenges(self):
        beat = Merkle.Merkle()

        # encode with 200 challenges
        with open('files/test.txt','rb') as file:
            (tag,state) = beat.encode(file,200)

        with self.assertRaises(HeartbeatError) as ex:
            for i in range(0,201):
                chal = beat.gen_challenge(state)

        ex_msg = ex.exception.message
        self.assertEqual("Out of challenges.",ex_msg)
        
    def test_comparison(self):
        k = os.urandom(32)
        k3 = os.urandom(32)
        beat1 = Merkle.Merkle(key=k)
        beat2 = Merkle.Merkle(key=k)
        beat3 = Merkle.Merkle(key=k3)
        
        s = os.urandom(32)
        s3 = os.urandom(32)
        with open('files/test.txt','rb') as file:
            (tag1,state1) = beat1.encode(file,200,s)
            file.seek(0)
            (tag2,state2) = beat2.encode(file,200,s)
            file.seek(0)
            (tag3,state3) = beat3.encode(file,200,s3)
        
        chal1 = beat1.gen_challenge(state1)
        chal2 = beat2.gen_challenge(state2)
        chal3 = beat3.gen_challenge(state3)
        
        with open('files/test.txt','rb') as file:
            proof1 = beat1.prove(file,chal1,tag1)
            file.seek(0)
            proof2 = beat2.prove(file,chal2,tag2)
            file.seek(0)
            proof3 = beat3.prove(file,chal3,tag3)
            
        self.assertEqual(beat1,beat2)
        self.assertNotEqual(beat1,beat3)
        
        self.assertEqual(tag1,tag2)
        self.assertNotEqual(tag1,tag3)
        
        self.assertEqual(state1,state2)
        self.assertNotEqual(state1,state3)
        
        self.assertEqual(chal1,chal2)
        self.assertNotEqual(chal1,chal3)
        
        self.assertEqual(proof1,proof2)
        self.assertNotEqual(proof1,proof3)


class TestCorrectness(unittest.TestCase):
    def test_correctness(self):
        GenericCorrectnessTests.generic_correctness_test(self,Merkle.Merkle)
    def test_scheme(self):
        GenericCorrectnessTests.generic_scheme_test(self,Merkle.Merkle)
    def test_repeated(self):
        GenericCorrectnessTests.generic_test_repeated_challenge(self,Merkle.Merkle)
        
        
if __name__ == '__main__':
    unittest.main()
