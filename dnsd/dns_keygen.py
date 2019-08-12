#!/usr/bin/python3
'''
Generate random keys and write the secrets.h and secrets.json files
'''
from random import sample
from Crypto import Random
import json

coding_table = ''.join(sample("abcdefghijklmnopqrstuvwxyz0123456789-", 32))
secret_key = Random.new().read(16)

with open('secrets.json', 'w') as f:
    json.dump({
       "secret_key": secret_key.hex(),
       "coding_table": coding_table
    }, f, indent=4)

with open('../src/secrets.h', 'w') as f:
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

print("wrote secrets.json and secrets.h")
