#!/usr/bin/python3
'''
Generate random keys and write the secrets.h and secrets.json files
'''
from random import sample
from Crypto import Random
import json
from os.path import isfile
import sys

fname_j = 'dnsd/secrets.json'
fname_h = 'src/secrets.h'
coding_table = ''.join(sample("abcdefghijklmnopqrstuvwxyz0123456789-", 32))
secret_key = Random.new().read(16)


def write_j(fname):
    with open(fname, 'w') as f:
        json.dump({
           "secret_key": secret_key.hex(),
           "coding_table": coding_table
        }, f, indent=4)
    print("wrote", fname, file=sys.stderr)


def write_h(fname):
    with open(fname, 'w') as f:
        f.write('#ifndef SECRETS_H_\n')
        f.write('#define SECRETS_H_\n')
        f.write('#define SECRET_KEY { \\\n\t')
        for i, c in enumerate(secret_key):
            if i > 0 and (i % 8) == 0:
                f.write('\\\n\t')
            f.write('0x{0:02x}, '.format(c))
        f.write('\\\n}\n')
        f.write('#define CODING_TABLE \"')
        f.write(coding_table)
        f.write('"\n')
        f.write('#endif /* SECRETS_H_ */\n')
    print("wrote", fname, file=sys.stderr)


if not isfile(fname_h):
    write_j(fname_j)
    write_h(fname_h)
else:
    print(fname_h, 'exists already', file=sys.stderr)
