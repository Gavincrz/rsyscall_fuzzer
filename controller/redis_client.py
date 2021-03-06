#!/usr/bin/env python3
import redis

try:
    r = redis.Redis(host='localhost', port=6379, db=0, socket_timeout=3)
    if r.set('foo', 'bar') != True:
        exit(-1)
    if r.get('foo') != b"bar":
        exit(-1)
    r.close()
except Exception as err:
    exit(-1)
else:
    exit(0)
