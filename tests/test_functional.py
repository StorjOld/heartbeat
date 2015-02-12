#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of Heartbeat: https://github.com/Storj/heartbeat
#
# The MIT License (MIT)
#
# Copyright (c) 2014 Paul Durivage <pauldurivage+git@gmail.com>, et al. for
#    Storj Labs
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

from __future__ import print_function

import time
import timeit
import unittest

from heartbeat.OneHash import OneHash


class Chunk(object):
    def __init__(self, file_path, num_challenges, root_seed):
        self.secret = b"mysecret"
        self.target_file = OneHash(file_path, self.secret)
        self.target_file.generate_challenges(num_challenges, root_seed)

    def challenge(self):
        return self.target_file.random_challenge()

    def response(self, answer):
        return self.target_file.check_answer(answer)


class Client(object):
    def __init__(self, file_path):
        self.target_file = OneHash(file_path, b"mysecret")

    def answer(self, challenge):
        return self.target_file.meet_challenge(challenge)


class Contract(object):
    def __init__(self, file_path, redundancy, num_challenges, root_seed):
        self.chunk_list = []
        for i in range(redundancy):
            self.chunk_list.append(
                Chunk(file_path, num_challenges, root_seed + bytes(i))
            )

    def send_contract(self):
        pass

    def run(self):
        for chunk in self.chunk_list:
            print(chunk.challenge())


class TestFunctional(unittest.TestCase):
    def setUp(self):
        self.file_path = "files/test.txt"
        self.file_path2 = "files/test2.txt"
        self.file_path3 = "files/test3.txt"
        self.size_path = "files/test4.txt"
        self.root_seed = b"myroot"

    def tearDown(self):
        del self.file_path
        del self.file_path2
        del self.file_path3
        del self.size_path
        del self.root_seed

    def test_heartbeat_and_challenge(self):
        file1 = OneHash(self.file_path, b"mysecret")
        file1.generate_challenges(10, self.root_seed)
        challenge = file1.random_challenge()

        # Create hash_response from seed and duplicate file
        file2 = OneHash(self.file_path2)
        answer = file2.meet_challenge(challenge)
        self.assertTrue(file1.check_answer(answer))

        # Create hash_answer from seed and edited file
        file3 = OneHash(self.file_path3)
        answer = file3.meet_challenge(challenge)

        # This should not match
        self.assertFalse(file1.check_answer(answer))

    def test_size(self):
        return  # this test takes a long time
        def num_challenges(number):
            file1 = OneHash(self.size_path, b"mysecret")
            file1.generate_challenges(number, self.root_seed)

        def size1():
            # 731 hours in a month
            num_challenges(1000)

        def size2():
            # 8766 hours in a year
            num_challenges(10000)

        # Time and Size of Challenges
        print("Month of Challenges (1 per hour):")
        print(str(timeit.timeit(size1, number=1)) + " seconds")
        print("Year of Challenges (1 per hour):")
        print(str(timeit.timeit(size2, number=1)) + " seconds")
        print("")

    def test_generate_many_challenges(self):
        num_challenges = 100
        root_seed = b"testing"

        # Start
        chunk = Chunk("files/test4.txt", num_challenges, root_seed)
        client = Client("files/test4.txt")

        for i in range(num_challenges):
            challenge = chunk.challenge()
            print("Node: c - " + str(challenge.seed))
            try:
                response = client.answer(challenge)
            except ValueError:
                response = "IO"
            # print("Client: a - " + str(response))
            correct = chunk.response(response)
            # print("Node: " + str(correct) + "\n")

            if not correct:
                break
            time.sleep(0.25)

    def test_challenges(self):
        contract = Contract("files/test4.txt", 3, 100, b"testing")
        contract.run()

if __name__ == '__main__':
    unittest.main()
