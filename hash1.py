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


MIN_NONCE = (0, 10000, 20000, 30000)
MAX_NONCE = (9999, 19999, 29999, 39999)

STDOUT_LOCK = mp.Lock()

class HashProc(mp.Process):

    def __init__(self, header, index):
        if 0 <= index <= 3:
            self.index = index
        else:
            raise ValueError("Index must be between 0-3")

        self.header = bytes(header, 'ascii')
        # instance queues
        self.NONCE_QUEUE = queue.Queue(50000)
        self.fh = open('%s%d.txt' % (header, index), 'w')
        super().__init__()


    def write(self, digest, nonce):
        STDOUT_LOCK.acquire()
        sys.stdout.write(f'{nonce},{digest}\n')
        STDOUT_LOCK.release()

    def getHash(self):
        nonce = self.NONCE_QUEUE.get()
        salted = b'%s%s' % (self.header,nonce.to_bytes(nonce.bit_length(), sys.byteorder))
        hashed = hashlib.sha256(salted)
        digest = hashed.digest()
        hexdigest = binascii.hexlify(digest)
        self.write(hexdigest, nonce)
        self.NONCE_QUEUE.task_done()

    def run(self):
        for nonce in range(MIN_NONCE[self.index], MAX_NONCE[self.index]):
            self.NONCE_QUEUE.put(nonce)
        while not self.NONCE_QUEUE.empty():
            self.getHash()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--blockheader', dest='header',
                        default='charles dale addis pantoga',
                        help='Last blocks\' hash')
    args = parser.parse_args()
    hashprocs = []
    for proc in (0, 1, 2, 3):
        hashproc = HashProc(header=args.header, index=proc)
        hashprocs.append(hashproc)
        hashprocs[proc].start()

    for proc in hashprocs:
        proc.join()
    sys.exit(0)
