#!/usr/bin/env python3
'''
Hasher
author: varcharlie
'''
import argparse
import hashlib
import binascii
import multiprocessing as mp
import queue
import sys
import threading

MIN_NONCE = (0, 100000, 200000, 300000)
MAX_NONCE = (99999, 199999, 299999, 399999)
MIN_INDEX = os.getenv('MIN_INDEX', 0)
MAX_INDEX = os.getenv('MAX_INDEX', 3)
stdout_lock = mp.Lock()

class HashProc(mp.Process):
    def __init__(self, header, index):
        if MIN_INDEX <= index <= MAX_INDEX:
            self.index = index
        else:
            raise ValueError("Index must be between 0-3")

        self.header = bytes(header, 'ascii')
        # instance queues
        self.nonce_queue = queue.Queue(50000)
        self.fh = open('%s%d.txt' % (header, index), 'w')
        self.run_lock = mp.Lock()
        super().__init__()


    def stderr(self, msg):
        stdout_lock.acquire()
        sys.stdout.write(f'{msg}\n')
        stdout_lock.release()

    def stdout(self, digest, nonce):
        stdout_lock.acquire()
        sys.stdout.write(f'{nonce},{digest}\n')
        stdout_lock.release()

    def getHash(self):
        if self.running:
            nonce = self.nonce_queue.get()
            salted = b'{0}{1}'.format(
                    self.header,
                    nonce.to_bytes(nonce.bit_length(), sys.byteorder)
                    )
            hashed = hashlib.sha256(salted)
            digest = hashed.digest()
            hexdigest = binascii.hexlify(digest)
            self.stdout(hexdigest, nonce)
            self.nonce_queue.task_done()
        return self.running

    def run(self):
        self.run_lock.acquire()
        self.running = True
        for nonce in range(MIN_NONCE[self.index], MAX_NONCE[self.index]):
            self.nonce_queue.put(nonce)
        while not self.nonce_queue.empty():
            if not self.getHash():
                self.stderr('Tried to getHash() while not running')
        self.run_lock.release()
        self.running = False


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--blockheader', dest='header',
                        default='charles dale addis pantoga',
                        help='Last blocks\' hash')
    args = parser.parse_args()
    hashprocs = []
    for proc in range(MIN_INDEX, MAX_INDEX+1):
        hashproc = HashProc(header=args.header, index=proc)
        hashprocs.append(hashproc)
        hashprocs[proc].start()

    for proc in hashprocs:
        proc.join()
    sys.exit(0)
