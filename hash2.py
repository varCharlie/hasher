#!/usr/bin/env python3
'''
Hash finder
author: varcharlie
'''

import argparse
import hashlib
import binascii
import multiprocessing as mp
import queue
import sys
import threading

# Global variable, initialized in main:
DIGEST_QUEUE = None


class HashProc(mp.Process):

    def __init__(self, header, index, min_nonce, max_nonce):
        if 0 <= index <= 3:
            self.index = index
        else:
            raise ValueError("Index must be between 0-3")

        self.min_nonce = min_nonce
        self.max_nonce = max_nonce
        self.header = bytes(header, 'ascii')
        # instance queues
        self.NONCE_QUEUE = queue.Queue(max_nonce-min_nonce)
        self.fh = open('%s%d.txt' % (header, index), 'w')
        super().__init__()


    def getHash(self):
        nonce = self.NONCE_QUEUE.get()
        plaintext = b'%s%s' % (self.header,nonce.to_bytes(nonce.bit_length(), sys.byteorder))
        hashed = hashlib.sha256(plaintext)
        digest = hashed.digest()
        hexdigest = binascii.hexlify(digest)
        DIGEST_QUEUE.put((plaintext, hexdigest))
        self.NONCE_QUEUE.task_done()

    def run(self):
        for nonce in range(self.min_nonce, self.max_nonce):
            self.NONCE_QUEUE.put(nonce)
        while True:
            self.getHash()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--blockheader', dest='header',
                        default='charles dale addis pantoga',
                        help='Last blocks\' hash')
    parser.add_argument('-m', '--maxnonce', dest='maxnonce', default=40000,
                        type=int, help='Max nonce value to hash with')
    parser.add_argument('-p', '--processes', dest='procs', default=4, type=int,
                        help='Number of processes to use')
    args = parser.parse_args()
    nonce_limits = list(range(0, args.maxnonce, args.procs))
    nonce_limits.append(args.maxnonce)
    hashprocs = mp.Queue(4)
    DIGEST_QUEUE = queue.Queue(args.maxnonce)
    for proc in range(0, args.procs):
        hashproc = HashProc(header=args.header, index=proc,
                        min_nonce=nonce_limits[proc],
                        max_nonce=nonce_limits[proc+1]-1)
        hashproc.start()
        hashprocs.put(hashproc)

    while not hashprocs.empty():
        hashprocs.get().join()

    while not DIGEST_QUEUE.empty():
        plaintext, hexdigest = DIGEST_QUEUE.get()
        sys.stdout.write(f'{plaintext}: {hexdigest}\n')
    sys.exit(0)
