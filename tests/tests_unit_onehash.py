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

from heartbeat.exc import HeartbeatError
from heartbeat.OneHash import OneHash,Challenge


class TestChallenge(unittest.TestCase):
    def setUp(self):
        self.challenge = Challenge([], [])

    def tearDown(self):
        del self.challenge

    def test_init(self):
        self.assertEqual(self.challenge.block, [])
        self.assertEqual(self.challenge.seed, [])
        self.assertIs(self.challenge.response, None)


class TestOneHash(unittest.TestCase):
    def setUp(self):
        self.file_loc = os.path.abspath('files/test.txt')
        self.secret = b"mysecret"
        self.hb = OneHash(self.file_loc, self.secret)

    def tearDown(self):
        del self.hb

    def test_initialization(self):
        self.assertEqual(self.hb.file_size, os.path.getsize(self.file_loc))
        if sys.version_info < (3, 0):
            self.assertIsInstance(self.hb.file_object, file)
        else:
            self.assertIsInstance(self.hb.file_object, io.BufferedReader)

        self.assertTrue(isinstance(self.hb.challenges, list))
        self.assertEqual(len(self.hb.challenges), 0)

        hb = OneHash(self.file_loc, os.urandom(32))
        self.assertTrue(hb.secret)
        self.assertTrue(len(hb.secret), 32)

    def test_initialization_fail(self):
        with self.assertRaises(HeartbeatError) as ex:
            OneHash('does/not/exist')

        ex_msg = ex.exception.message
        self.assertEqual('does/not/exist not found', ex_msg)

    def test_generate_seeds(self):
        integer = random.randint(0, 65535)
        decimal_ = Decimal(random.random()) + 5
        hashobj = hashlib.sha256(os.urandom(24))
        byteobj = os.urandom(32)
        hexdigest = hashlib.sha256(os.urandom(24)).hexdigest()

        seeds = self.hb.generate_seeds(4, bytes(integer), self.secret)
        self.assertEqual(len(seeds), 4)

        seeds = self.hb.generate_seeds(4, decimal_, self.secret)
        self.assertEqual(len(seeds), 4)
        for seed in seeds:
            self.assertIsInstance(seed, bytes)

        seeds = self.hb.generate_seeds(4, hashobj, self.secret)
        self.assertEqual(len(seeds), 4)
        for seed in seeds:
            self.assertIsInstance(seed, bytes)
            
        seeds = self.hb.generate_seeds(4, byteobj, self.secret)
        self.assertEqual(len(seeds), 4)
        for seed in seeds:
            self.assertIsInstance(seed, bytes)

        seeds = self.hb.generate_seeds(4, hexdigest, self.secret)
        self.assertEqual(len(seeds), 4)
        for seed in seeds:
            self.assertIsInstance(seed, bytes)

    def test_generate_seeds_invalid_num(self):
        integer = random.randint(0, 65535)
        with self.assertRaises(HeartbeatError) as ex:
                self.hb.generate_seeds(-1, integer, self.secret)
        ex_msg = ex.exception.message
        self.assertEqual('-1 is not greater than 0', ex_msg)

    def test_denerate_seeds_no_secret(self):
        digest = hashlib.sha256(os.urandom(24)).digest()
        with self.assertRaises(HeartbeatError) as ex:
            self.hb.generate_seeds(4, digest, None)
        ex_msg = ex.exception.message
        self.assertEqual('secret can not be of type NoneType', ex_msg)

    def test_generate_seeds_deterministic(self):
        digest = hashlib.sha256(os.urandom(24)).digest()

        seed_group_1 = self.hb.generate_seeds(5, digest, self.secret)
        seed_group_2 = self.hb.generate_seeds(5, digest, self.secret)
        self.assertEqual(seed_group_1, seed_group_2)

    def test_pick_blocks(self):
        integer = random.randint(0, 65535)
        decimal_ = Decimal(random.random()) + 5
        hashobj = hashlib.sha256(os.urandom(24))
        bytesobj = os.urandom(32)
        hexdigest = hashlib.sha256(os.urandom(24)).hexdigest()

        seeds = self.hb.pick_blocks(4, integer)
        self.assertEqual(len(seeds), 4)

        seeds = self.hb.pick_blocks(4, decimal_)
        self.assertEqual(len(seeds), 4)
        for seed in seeds:
            self.assertIsInstance(seed, int)

        seeds = self.hb.pick_blocks(4, hashobj)
        self.assertEqual(len(seeds), 4)
        for seed in seeds:
            self.assertIsInstance(seed, int)

        seeds = self.hb.pick_blocks(4, bytesobj)
        self.assertEqual(len(seeds), 4)
        for seed in seeds:
            self.assertIsInstance(seed, int)
            
        seeds = self.hb.pick_blocks(4, hexdigest)
        self.assertEqual(len(seeds), 4)
        for seed in seeds:
            self.assertIsInstance(seed, int)

        with self.assertRaises(HeartbeatError) as ex:
                self.hb.pick_blocks(-1, integer)
        ex_msg = ex.exception.message
        self.assertEqual('-1 is not greater than 0', ex_msg)

    def test_pick_blocks_deterministic(self):
        digest = hashlib.sha256(os.urandom(24)).digest()

        seed_group_1 = self.hb.pick_blocks(5, digest)
        seed_group_2 = self.hb.pick_blocks(5, digest)
        self.assertEqual(seed_group_1, seed_group_2)

    def test_meet_challenge(self):
        block = 0
        root_seed = os.urandom(32)
        challenge = Challenge(block, root_seed)

        chunk_size = min(1024, self.hb.file_size // 10)

        self.hb.file_object.seek(block)
        h = hashlib.sha256()
        h.update(self.hb.file_object.read(chunk_size))
        h.update(root_seed)
        digest = h.digest()

        result = self.hb.meet_challenge(challenge)
        self.assertEqual(digest, result)

    def test_meet_challenge_near_eof(self):
        block = 3100
        root_seed = os.urandom(32)
        challenge = Challenge(block, root_seed)
        chunk_size = min(1024, self.hb.file_size // 10)

        self.assertTrue(challenge.block > (self.hb.file_size - chunk_size))

        self.hb.file_object.seek(block)
        end_slice = block - (self.hb.file_size - chunk_size)
        h = hashlib.sha256()
        h.update(self.hb.file_object.read(end_slice))
        self.hb.file_object.seek(0)
        h.update(self.hb.file_object.read(chunk_size - end_slice))
        h.update(root_seed)
        digest = h.digest()

        result = self.hb.meet_challenge(challenge)
        self.assertEqual(digest, result)

    def test_generate_challenges(self):
        num = random.randint(5, 10)
        digest = hashlib.sha256(os.urandom(24)).digest()

        self.hb.generate_challenges(num, digest)
        for item in self.hb.challenges:
            self.assertIsInstance(item, Challenge)

        seeds = self.hb.generate_seeds(num, digest, self.secret)
        blocks = self.hb.pick_blocks(num, digest)

        for index in range(num):
            challenge = self.hb.challenges[index]
            self.assertEqual(challenge.seed, seeds[index])
            self.assertEqual(challenge.block, blocks[index])
            response = self.hb.meet_challenge(self.hb.challenges[index])
            self.assertEqual(response, self.hb.challenges[index].response)

    def test_check_answer(self):
        num = 1
        digest = hashlib.sha256(os.urandom(24)).digest()
        self.hb.generate_challenges(num, digest)

        value = self.hb.challenges[0].response
        result = self.hb.check_answer(value)
        self.assertIs(True, result)

    def test_check_answer_wrong_hash(self):
        num = 1
        digest = hashlib.sha256(os.urandom(24)).digest()
        self.hb.generate_challenges(num, digest)
        value = "test value that doesn't matter.  ;)"
        result = self.hb.check_answer(value)
        self.assertIs(False, result)

    def test_delete_challenge(self):
        num = 5
        digest = hashlib.sha256(os.urandom(24)).digest()
        self.hb.generate_challenges(num, digest)

        choice = self.hb.challenges[2].response
        result = self.hb.delete_challenge(choice)
        self.assertIs(result, True)
        self.assertTrue(len(self.hb.challenges), 4)

    def test_delete_challenge_wrong_hash(self):
        num = 5
        digest = hashlib.sha256(os.urandom(24)).digest()
        self.hb.generate_challenges(num, digest)

        choice = b"invalid hash that doesn't matter"
        result = self.hb.delete_challenge(choice)
        self.assertIs(result, False)
        self.assertTrue(len(self.hb.challenges), 5)

    def test_random_challenge(self):
        num = 5
        digest = hashlib.sha256(os.urandom(24)).digest()
        self.hb.generate_challenges(num, digest)

        rand_chal = self.hb.random_challenge()
        self.assertIsInstance(rand_chal, Challenge)
        found = False
        for challenge in self.hb.challenges:
            if challenge.block == rand_chal.block:
                found = True
        self.assertIs(found, True)

    def test_challenges_size(self):
        num = 5
        digest = hashlib.sha256(os.urandom(24)).digest()
        self.hb.generate_challenges(num, digest)

        self.assertEqual(self.hb.challenges_size,
                         sys.getsizeof(self.hb.challenges))

if __name__ == '__main__':
    unittest.main()
