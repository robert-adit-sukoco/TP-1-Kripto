from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class XTSAESMode:
    def __init__(self, key, tweak):
        self.aes = AES.new(key[:32], AES.MODE_ECB)
        self.tweak = AES.new(key[32:], AES.MODE_ECB).encrypt(tweak)

    def encrypt(self, data):
        tweak = self.tweak[:]

        blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
        if len(blocks[-1]) == 16:
            blocks.append(b'')

        for i in range(0, len(blocks) - 2):
            blocks[i] = self.__process_block_encrypt(blocks[i], tweak)
            tweak = self.__calculate_next_tweak(tweak)

        partial_length = len(blocks[-1])

        if partial_length == 0: # multiple of block size
            blocks[-2] = self.__process_block_encrypt(blocks[-2], tweak)
        else: # not multiple of block size
            first_tweak = tweak
            second_tweak = self.__calculate_next_tweak(tweak)
            cc = self.__process_block_encrypt(blocks[-2], first_tweak)
            pp = blocks[-1] + cc[partial_length:]
            blocks[-1] = cc[:partial_length]
            blocks[-2] = self.__process_block_encrypt(pp, second_tweak)

        return b''.join(blocks)


    def decrypt(self, data):
        tweak = self.tweak[:]

        blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
        if len(blocks[-1]) == 16:
            blocks.append(b'')

        for i in range(0, len(blocks) - 2):
            blocks[i] = self.__process_block_decrypt(blocks[i], tweak)
            tweak = self.__calculate_next_tweak(tweak)

        partial_length = len(blocks[-1])

        if partial_length == 0: # multiple of block size
            blocks[-2] = self.__process_block_decrypt(blocks[-2], tweak)
        else: # not multiple of block size
            first_tweak = self.__calculate_next_tweak(tweak)
            second_tweak = tweak
            cc = self.__process_block_decrypt(blocks[-2], first_tweak)
            pp = blocks[-1] + cc[partial_length:]
            blocks[-1] = cc[:partial_length]
            blocks[-2] = self.__process_block_decrypt(pp, second_tweak)

        return b''.join(blocks)

    
    def __process_block_encrypt(self, block, tweak):
        new_block = map(lambda x, y: x ^ y, block, tweak)
        new_block = self.aes.encrypt(new_block)
        new_block = map(lambda x, y: x ^ y, new_block, tweak)

        return bytearray(new_block)


    def __process_block_decrypt(self, block, tweak):
        new_block = map(lambda x, y: x ^ y, block, tweak)
        new_block = self.aes.decrypt(new_block)
        new_block = map(lambda x, y: x ^ y, new_block, tweak)

        return bytearray(new_block)


    def __calculate_next_tweak(self, tweak):
        next_tweak = bytearray()

        carry_in = 0
        carry_out = 0

        for j in range(0, 16):
            carry_out = (tweak[j] >> 7) & 1
            next_tweak.append(((tweak[j] << 1) + carry_in) & 0xFF)
            carry_in = carry_out

        if carry_out:
            next_tweak[0] ^= 0x87

        return next_tweak