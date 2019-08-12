from Crypto.Cipher import AES
from Crypto import Random
from math import ceil


class Crc16:
    ''' horribly inefficient implemetation of Modbus style CRC16 '''

    def __init__(self):
        self._resetRunnningCRC()

    def _resetRunnningCRC(self):
        self.c = 0xFFFF

    def _runningCRC(self, inputByte):
        self.c ^= inputByte
        self.c &= 0xFFFF
        for b in range(8):             # For each bit in the byte
            if self.c & 1:
                self.c = (self.c >> 1) ^ 0xA001
            else:
                self.c = (self.c >> 1)
            self.c &= 0xFFFF

    def getCrc(self, dataBytes):
        self._resetRunnningCRC()
        for b in dataBytes:
            self._runningCRC(b)
        return self.c.to_bytes(2, 'big')


class DnsCoder:
    LBL_LEN = 63

    def __init__(self, secret_key, coding_table):
        ''' helper class to convert bytes into encrypted base32 DNS names
        secret_key = 16, 24 or 32 byte long secret key for AES
        coding_table = 32 bytes used as alphabet lookup table for base32
        '''
        self.coding_table = coding_table
        self.decoding_table = {}
        for i, c in enumerate(coding_table.lower()):
            self.decoding_table[c] = i
        self.ecipher = AES.new(
            secret_key, AES.MODE_CBC, Random.new().read(AES.block_size)
        )
        self.dcipher = AES.new(
            secret_key, AES.MODE_CBC, Random.new().read(AES.block_size)
        )
        self.crc = Crc16()

    def _enc_b32(self, pl):
        ''' pl [bytes] --> base32 string '''
        chars = ''
        res = int.from_bytes(pl, 'little')
        nBits = len(pl) * 8
        while nBits > 0:
            chars += self.coding_table[res & 0x1F]
            res >>= 5
            nBits -= 5
        return chars

    def _dec_b32(self, chars):
        ''' base32 string --> pl [bytes] '''
        res = 0
        for i, c in enumerate(chars.lower()):
            res |= self.decoding_table[c] << (i * 5)
        return res.to_bytes(ceil(len(chars) * 5 / 8), 'little')

    def dns_enc(self, pl):
        # Add CRC16 fields
        pl = bytes(pl) + self.crc.getCrc(pl)

        # Pad pl to mod. 16 bytes
        n_pad = 16 - (len(pl) % 16)
        pl += bytes([n_pad] * n_pad)

        # AES encrypt
        msg = self.ecipher.encrypt(pl)
        # hprint(msg)

        # base32 encode and add some . every 63 characters
        msg32 = self._enc_b32(msg)
        lMax = DnsCoder.LBL_LEN
        msg32 = '.'.join(
            [msg32[i: i + lMax] for i in range(0, len(msg32), lMax)]
        )
        return msg32

    def dns_dec(self, msg32):
        """ decode URL string and return payload as bytes """
        # remove '.', base32 decode
        msg32 = msg32.replace('.', '').lower()
        msg = self._dec_b32(msg32)

        # msg must be a integer multiple of 16 bytes long,
        # clip the eventual \x00 at the end
        msg = msg[:len(msg) - (len(msg) % 16)]

        # AES decrypt
        pl = self.dcipher.decrypt(msg)

        # remove padding
        pl = pl[: len(pl) - pl[-1]]

        # check crc
        crc_r = pl[-2:]
        pl = pl[:-2]
        if self.crc.getCrc(pl) != crc_r:
            raise RuntimeError("CRC ERR")
        return pl
