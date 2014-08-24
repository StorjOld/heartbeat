#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import copy
import random
import hashlib
import os.path

from .exc import HeartbeatError


class Challenge(object):
    """ The Challenge class represents a challenge one node can pose to
    another when requesting verification that they have a complete version
    of a specific file.
    """

    def __init__(self, position, seed):
        self.position = position
        self.seed = seed
        self.response = None

    def get_without_answer(self):
        """Provide a challenge for sending to other nodes."""
        return Challenge(self.position, self.seed)

    def get_position(self):
        """Provide the position in the file this challenge focuses on."""
        return self.position

    def get_seed(self):
        """Provide the seed used as input to this challenge block's hash."""
        return self.seed

    def get_response(self):
        """
        Provide the expected response; a succesfully completed challenge.
        will match this.
        """
        return self.response

    def set_response(self, response):
        self.response = response


class HeartBeat:
    """
    A small library used to create and verify hash challenges
    so Node A can verify that Node B has a specified file.
    """

    def __init__(self, file_path):
        # Check if the file exists
        if os.path.isfile(file_path):
            self.file_size = os.path.getsize(file_path)
            self.file_object = open(file_path, "rb")
        else:
            raise IOError("File Not Found.")

        # Challenges is a list of 2-tuples (seed, hash_response)
        self.challenges = []

    def gen_challenges(self, num, root_seed):
        """
        Generate the specified number of hash challenges.

        Arguments:
        num -- The number of hash challenges we want to generate.
        root_seed -- Some value that we use to generate our seeds from.
        """

        # Generate a series of seeds
        seeds = self.gen_seeds(num, root_seed)
        blocks = self.pick_blocks(num, root_seed)

        # List of 2-tuples (seed, hash_response)
        challenges = []

        # Generate the corresponding hash for each seed
        for i in range(num):
            challenges.append(Challenge(blocks[i], seeds[i]))
            response = self.meet_challenge(challenges[i])
            challenges[i].set_response(response)

        # Save challenges
        self.challenges = challenges

    def meet_challenge(self, challenge):
        """
        Get the SHA256 hash of a specific file block plus the provided
        seed.

        The default block size is one tenth of the file. If the file is
        larger than 10KB, 1KB is used as the block size.
        """
        h = hashlib.sha256()
        CHUNK_SIZE = min(1024, self.file_size // 10)
        seed = bytes(str(challenge.get_seed()), 'utf-8')

        self.file_object.seek(challenge.get_position())

        if (challenge.get_position() > self.file_size - CHUNK_SIZE):
            end_slice = (
                challenge.get_position() - (self.file_size - CHUNK_SIZE)
            )
            h.update(self.file_object.read(end_slice))
            self.file_object.seek(0)
            h.update(self.file_object.read(CHUNK_SIZE - end_slice))
        else:
            h.update(self.file_object.read(CHUNK_SIZE))

        h.update(seed)

        return h.hexdigest()

    def gen_seeds(self, num, root_seed):
        """
        Deterministically generate list of seeds from a root seed.

        Arguments:
        num -- Numbers of seeds to generate.
        root_seed -- Seed to start off with.
        """
        # Generate a starting seed from the root
        seeds = []
        random.seed(root_seed)
        tmp_seed = random.random()

        # Deterministically generate the rest of the seeds
        for x in range(num):
            seeds.append(tmp_seed)
            random.seed(tmp_seed)
            tmp_seed = random.random()

        return seeds

    def pick_blocks(self, num, root_seed):
        """
        Pick a set of positions to start reading blocks from the
        file that challenges are created for.

        Positions are guaranteed to be within the bounds of the file.
        """
        blocks = []
        random.seed(root_seed)

        for i in range(num):
            blocks.append(random.randint(0, self.file_size - 1))

        return blocks

    def check_answer(self, hash_answer):
        """
        Check if the returned hash is in our challenges list.

        Arguments:
        hash_answer -- a hash that we compare to our list of challenges.
        """
        for a_challenge in self.challenges:
            if a_challenge.get_response() == hash_answer:
                # If we don't disgard a used challenge then a node
                # could fake having the file because it already
                # knows the proper response
                # self.delete_challenge(hash_answer)
                return True
        return False

    def delete_challenge(self, hash_answer):
        """Delete challenge from our list of challenges."""
        for a_challenge in self.challenges:
            if a_challenge.get_response() == hash_answer:
                self.challenges.remove(a_challenge)
                return True
        return False

    def get_challenge(self):
        """Get a random challenge."""
        return random.choice(self.challenges).get_without_answer()

    def challenges_size(self):
        """Get bytes size of our challenges."""
        return sys.getsizeof(self.challenges)
