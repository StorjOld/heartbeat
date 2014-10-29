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

import unittest
from heartbeat.exc import HeartbeatError
import heartbeat
from heartbeat import Heartbeat

    
class TestHeartbeat(unittest.TestCase):
    def test_usage(self):    
        beat = Heartbeat()
        
        public_beat = beat.get_public()
        
        with open('files/test.txt','rb') as file:
            (tag,state) = beat.encode(file)
            
        challenge = beat.gen_challenge(state)
        
        with open('files/test.txt','rb') as file:
            proof = public_beat.prove(file,challenge,tag)
        
        is_valid = beat.verify(proof,challenge,state)
        if (is_valid):
            print('file is stored by the server')
        else:
            print('file proof invalid')
        
        self.assertTrue(is_valid)
        
    def test_type(self):
        b = Heartbeat()
        
        self.assertIsInstance(b, heartbeat.Swizzle.Swizzle)
        
class TestHeartbeatError(unittest.TestCase):
        
    def test_message(self):
        with self.assertRaises(HeartbeatError) as ex:
            raise HeartbeatError("test error")
            
        self.assertEqual(str(ex.exception),"test error")
        
if __name__ == '__main__':
    unittest.main()
