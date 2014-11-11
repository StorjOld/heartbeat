#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of Heartbeat: https://github.com/Storj/heartbeat
#
# The MIT License (MIT)
#
# Copyright (c) 2014 Storj Labs, Paul Durivage, et al.
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

import sys
import copy
import random
import hashlib
import os.path

from ..exc import HeartbeatError


class Challenge(object):

    """ The Challenge class represents a challenge one node can pose to
    another when requesting verification that they have a complete version
    of a specific file.
    """

    def __init__(self, block, seed):
        """ Initialization method

        :param block: Position at which to start a challenge check
        :param seed: Seed as a hashable object
        """
        self.block = block
        self.seed = seed
        self.response = None

    @property
    def without_answer(self):
        """ Provide a challenge for sending to other nodes. """
        new = copy.copy(self)
        del new.response
        return new


class OneHash(object):

    """ A small library used to create and verify hash challenges
    so Node A can verify that Node B has a specified file.
    """

    def __init__(self, filepath, secret=None):
        # Check if the file exists
        """ Initialization method

        :param filepath: Valid path to file
        :raise HeartbeatError: If file path does not exist
        """
        if os.path.isfile(filepath):
            self.file_size = os.path.getsize(filepath)
            self.file_object = open(filepath, "rb")
        else:
            raise HeartbeatError("%s not found" % filepath)

        self.secret = secret

        # Challenges is a list of 2-tuples (seed, hash_response)
        self.challenges = []

    def __del__(self):
        try:
            self.file_object.close()
        except:
            pass

    def generate_challenges(self, num, root_seed):
        """ Generate the specified number of hash challenges.

        :param num: The number of hash challenges we want to generate.
        :param root_seed: Some value that we use to generate our seeds from.
        """

        # Generate a series of seeds
        seeds = self.generate_seeds(num, root_seed, self.secret)
        blocks = self.pick_blocks(num, root_seed)

        # List of 2-tuples (seed, hash_response)
        self.challenges = []

        # Generate the corresponding hash for each seed
        for i in range(num):
            self.challenges.append(Challenge(blocks[i], seeds[i]))
            response = self.meet_challenge(self.challenges[i])
            self.challenges[i].response = response

    def meet_challenge(self, challenge):
        """ Get the SHA256 hash of a specific file block plus the provided
        seed. The default block size is one tenth of the file. If the file is
        larger than 10KB, 1KB is used as the block size.

        :param challenge: challenge as a `Challenge <heartbeat.Challenge>`
        object
        """
        chunk_size = min(1024, self.file_size // 10)
        seed = challenge.seed

        h = hashlib.sha256()
        self.file_object.seek(challenge.block)

        if challenge.block > (self.file_size - chunk_size):
            end_slice = (
                challenge.block - (self.file_size - chunk_size)
            )
            h.update(self.file_object.read(end_slice))
            self.file_object.seek(0)
            h.update(self.file_object.read(chunk_size - end_slice))
        else:
            h.update(self.file_object.read(chunk_size))

        h.update(seed)

        return h.digest()

    @staticmethod
    def generate_seeds(num, root_seed, secret):
        """ Deterministically generate list of seeds from a root seed.

        :param num: Numbers of seeds to generate as int
        :param root_seed: Seed to start off with.
        :return: seed values as a list of length num
        """
        # Generate a starting seed from the root
        if num < 0:
            raise HeartbeatError('%s is not greater than 0' % num)

        if secret is None:
            raise HeartbeatError('secret can not be of type NoneType')

        seeds = []
        try:
            tmp_seed = hashlib.sha256(root_seed).digest()
        except TypeError:
            tmp_seed = hashlib.sha256(str(root_seed).encode()).digest()

        # Deterministically generate the rest of the seeds
        for x in range(num):
            seeds.append(tmp_seed)
            h = hashlib.sha256(tmp_seed)
            h.update(secret)
            tmp_seed = h.digest()

        return seeds

    def pick_blocks(self, num, root_seed):
        """ Pick a set of positions to start reading blocks from the file
        that challenges are created for. This is a deterministic
        operation. Positions are guaranteed to be within the bounds of the
        file.

        :param num: Number of blocks to pick
        :param root_seed: Seed with which begin picking blocks.
        :return: block values as a list
        """
        if num < 0:
            raise HeartbeatError('%s is not greater than 0' % num)

        blocks = []
        random.seed(root_seed)

        for i in range(num):
            blocks.append(random.randint(0, self.file_size - 1))

        return blocks

    def check_answer(self, hash_answer):
        """ Check if the returned hash is in our challenges list.

        :param hash_answer: Hash that we compare to our list of challenges
        :return: boolean indicating if answer is correct, True, or not, False
        """
        for challenge in self.challenges:
            if challenge.response == hash_answer:
                # If we don't discard a used challenge then a node
                # could fake having the file because it already
                # knows the proper response
                self.delete_challenge(hash_answer)
                return True
        return False

    def delete_challenge(self, hash_answer):
        """ Delete challenge from our list of challenges.

        :param hash_answer:  A hash as a string
        :return: Boolean indicating whether hash existed and was deleted
        """
        for challenge in self.challenges:
            if challenge.response == hash_answer:
                self.challenges.remove(challenge)
                return True
        return False

    def random_challenge(self):
        """ Get a random challenge.

        :return: A challenge object at random
        """
        choice = random.choice(self.challenges)
        return choice.without_answer

    @property
    def challenges_size(self):
        """ Get bytes size of our challenges.

        :return: Size of the challenges object in memory as an integer.  See
        sys.getsizeof for more information
        """
        return sys.getsizeof(self.challenges)
