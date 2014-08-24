#!/usr/bin/env python
# -*- coding: utf-8 -*-


class HeartbeatError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message
