#!/usr/bin/env python
# -*- coding: utf-8 -*-
import hashlib
import io
import os
import sys
import random
import unittest
from decimal import Decimal

from heartbeat.heartbeat import Heartbeat, Challenge
from heartbeat.exc import HeartbeatError


class TestChallenge(unittest.TestCase):
    def setUp(self):
        self.challenge = Challenge([], [])

    def tearDown(self):
        del self.challenge

    def test_init(self):
        self.assertEqual(self.challenge.block, [])
        self.assertEqual(self.challenge.seed, [])
        self.assertIs(self.challenge.response, None)


class TestHeartbeat(unittest.TestCase):
    def setUp(self):
        self.file_loc = os.path.abspath('tests/files/test.txt')
        self.hb = Heartbeat(self.file_loc)

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

    def test_initialization_fail(self):
        with self.assertRaises(HeartbeatError) as ex:
            Heartbeat('does/not/exist')

        ex_msg = ex.exception.message
        self.assertEqual('does/not/exist not found', ex_msg)

    def test_generate_seeds(self):
        integer = random.randint(0, 65535)
        decimal_ = Decimal(random.random()) + 5
        hashobj = hashlib.sha256(os.urandom(24))
        hexdigest = hashlib.sha256(os.urandom(24)).hexdigest()

        seeds = self.hb.generate_seeds(4, integer)
        self.assertEqual(len(seeds), 4)

        seeds = self.hb.generate_seeds(4, decimal_)
        self.assertEqual(len(seeds), 4)
        for seed in seeds:
            self.assertIsInstance(seed, float)

        seeds = self.hb.generate_seeds(4, hashobj)
        self.assertEqual(len(seeds), 4)
        for seed in seeds:
            self.assertIsInstance(seed, float)

        seeds = self.hb.generate_seeds(4, hexdigest)
        self.assertEqual(len(seeds), 4)
        for seed in seeds:
            self.assertIsInstance(seed, float)

        with self.assertRaises(HeartbeatError) as ex:
                self.hb.generate_seeds(-1, integer)
        ex_msg = ex.exception.message
        self.assertEqual('-1 is not greater than 0', ex_msg)

    def test_generate_seeds_deterministic(self):
        hexdigest = hashlib.sha256(os.urandom(24)).hexdigest()

        seed_group_1 = self.hb.generate_seeds(5, hexdigest)
        seed_group_2 = self.hb.generate_seeds(5, hexdigest)
        self.assertEqual(seed_group_1, seed_group_2)

    def test_pick_blocks(self):
        integer = random.randint(0, 65535)
        decimal_ = Decimal(random.random()) + 5
        hashobj = hashlib.sha256(os.urandom(24))
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

        seeds = self.hb.pick_blocks(4, hexdigest)
        self.assertEqual(len(seeds), 4)
        for seed in seeds:
            self.assertIsInstance(seed, int)

        with self.assertRaises(HeartbeatError) as ex:
                self.hb.pick_blocks(-1, integer)
        ex_msg = ex.exception.message
        self.assertEqual('-1 is not greater than 0', ex_msg)

    def test_pick_blocks_deterministic(self):
        hexdigest = hashlib.sha256(os.urandom(24)).hexdigest()

        seed_group_1 = self.hb.pick_blocks(5, hexdigest)
        seed_group_2 = self.hb.pick_blocks(5, hexdigest)
        self.assertEqual(seed_group_1, seed_group_2)

    def test_meet_challenge(self):
        block = 0
        root_seed = random.random()
        challenge = Challenge(block, root_seed)

        chunk_size = min(1024, self.hb.file_size // 10)
        self.assertEqual(chunk_size, 312)

        self.hb.file_object.seek(block)
        h = hashlib.sha256()
        h.update(self.hb.file_object.read(312))
        h.update(bytes(str(root_seed)))
        hexdigest = h.hexdigest()

        result = self.hb.meet_challenge(challenge)
        self.assertEqual(hexdigest, result)

    def test_meet_challenge_near_eof(self):
        block = 3100
        root_seed = random.random()
        challenge = Challenge(block, root_seed)
        chunk_size = min(1024, self.hb.file_size // 10)

        self.assertTrue(challenge.block > (self.hb.file_size - chunk_size))

        self.hb.file_object.seek(block)
        end_slice = block - (self.hb.file_size - chunk_size)
        h = hashlib.sha256()
        h.update(self.hb.file_object.read(end_slice))
        self.hb.file_object.seek(0)
        h.update(self.hb.file_object.read(312 - end_slice))
        h.update(bytes(str(root_seed)))
        hexdigest = h.hexdigest()

        result = self.hb.meet_challenge(challenge)
        self.assertEqual(hexdigest, result)

    def test_generate_challenges(self):
        num = random.randint(5, 10)
        hexdigest = hashlib.sha256(os.urandom(24)).hexdigest()

        self.hb.generate_challenges(num, hexdigest)
        for item in self.hb.challenges:
            self.assertIsInstance(item, Challenge)

        seeds = self.hb.generate_seeds(num, hexdigest)
        blocks = self.hb.pick_blocks(num, hexdigest)

        for index in range(num):
            challenge = self.hb.challenges[index]
            self.assertEqual(challenge.seed, seeds[index])
            self.assertEqual(challenge.block, blocks[index])
            response = self.hb.meet_challenge(self.hb.challenges[index])
            self.assertEqual(response, self.hb.challenges[index].response)

    def test_check_answer(self):
        num = 1
        hexdigest = hashlib.sha256(os.urandom(24)).hexdigest()
        self.hb.generate_challenges(num, hexdigest)

        value = self.hb.challenges[0].response
        result = self.hb.check_answer(value)
        self.assertIs(True, result)

    def test_check_answer_wrong_hash(self):
        num = 1
        hexdigest = hashlib.sha256(os.urandom(24)).hexdigest()
        self.hb.generate_challenges(num, hexdigest)
        value = "test value that doesn't matter.  ;)"
        result = self.hb.check_answer(value)
        self.assertIs(False, result)

    def test_delete_challenge(self):
        num = 5
        hexdigest = hashlib.sha256(os.urandom(24)).hexdigest()
        self.hb.generate_challenges(num, hexdigest)

        choice = self.hb.challenges[2].response
        result = self.hb.delete_challenge(choice)
        self.assertIs(result, True)
        self.assertTrue(len(self.hb.challenges), 4)

    def test_delete_challenge_wrong_hash(self):
        num = 5
        hexdigest = hashlib.sha256(os.urandom(24)).hexdigest()
        self.hb.generate_challenges(num, hexdigest)

        choice = "invalid hash that doesn't matter"
        result = self.hb.delete_challenge(choice)
        self.assertIs(result, False)
        self.assertTrue(len(self.hb.challenges), 5)

    def test_random_challenge(self):
        num = 5
        hexdigest = hashlib.sha256(os.urandom(24)).hexdigest()
        self.hb.generate_challenges(num, hexdigest)

        rand_chal = self.hb.random_challenge()
        self.assertIsInstance(rand_chal, Challenge)
        found = False
        for challenge in self.hb.challenges:
            if challenge.block == rand_chal.block:
                found = True
        self.assertIs(found, True)

    def test_challenges_size(self):
        num = 5
        hexdigest = hashlib.sha256(os.urandom(24)).hexdigest()
        self.hb.generate_challenges(num, hexdigest)

        self.assertEqual(self.hb.challenges_size, sys.getsizeof(self.hb.challenges))
