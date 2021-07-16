
class AES():
    
    def __init__(self, key, key_type="plain"):
        self.key = key
        
        self.sbox = [
            [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76], # 0
            [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0], # 1
            [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15], # 2
            [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75], # 3
            [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84], # 4 
            [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf], # 5
            [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8], # 6
            [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2], # 7
            [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73], # 8
            [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb], # 9
            [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79], # 10
            [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08], # 11 
            [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a], # 12
            [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e], # 13
            [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf], # 14
            [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16], # 15
        ]

        self.inv_sbox = [
            [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb], # 0
            [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb], # 1
            [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e], # 2 
            [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25], # 3
            [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92], # 4
            [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84], # 5
            [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06], # 6
            [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b], # 7
            [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73], # 8
            [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e], # 9
            [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b], # 10
            [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4], # 11
            [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f], # 12
            [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef], # 13
            [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61], # 14
            [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d] # 15
        ]

        self.rcon = [
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
            0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
            0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
            0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39
        ]
        self.setup(key_type)

    def setup(self, mode_key):
        if mode_key == "plain":
            time_key = []
            for x in self.key:
                sx = str(hex(ord(x))).replace("0x", "")
                if len(sx) == 1:
                    sx = "0" + sx
                time_key.append(int(sx, 16))
            self.key = time_key
        elif mode_key == "hex":
            time_key = []
            end, sx = 0, ""
            for i,v in enumerate(list(self.key)):
                sx += v
                end += 1
                if end == 2:
                    time_key.append(int(sx, 16))
                    end = 0
                    sx = ""
            self.key = time_key
        if len(self.key) == 16:
            self.Nk = 4
            self.Nb = 4
            self.Nr = 10 
        elif len(self.key) == 24:
            self.Nk = 6
            self.Nb = 4
            self.Nr = 12 
        elif len(self.key) == 32:
            self.Nk = 8
            self.Nb = 4
            self.Nr = 14 
        self.key = self.key_expansion(self.key)

    def key_expansion(self, key):
        def xor(a,b):
            if type(a) != list:
                a = [a,0,0,0]
            if type(b) != list:
                b = [b,0,0,0]
            return [c ^ d for c,d in zip(a,b)]
        def subwords(key_change):
            time_block = []
            for y in key_change:
                y = str(hex(y)).replace("0x", "")
                if len(y) == 1:
                    y = "0" + y
                y = self.sbox[int(y[0], 16)][int(y[1], 16)]
                time_block.append(y)
            return time_block
        def rotwords(key_change):
            return key_change[1:] + key_change[:1]
        time_key = []
        for i in range(self.Nk):
            sx = [self.key[4*i], self.key[4*i+1], self.key[4*i+2], self.key[4*i+3]]
            time_key.append(sx)
        for v in range(self.Nk, self.Nb*(self.Nr + 1)):
            temp = time_key[v - 1]
            if v % self.Nk == 0:
                temp = xor(subwords(rotwords(temp)), self.rcon[v//self.Nk])
            elif self.Nk > 6 and v % self.Nk == 4:
                temp = subwords(temp)
            time_key.append(xor(time_key[v-self.Nk], temp))
        return time_key

    def subbytes(self, block):
        sub_block = []
        for x in block:
            time_block = []
            for y in x:
                y = str(hex(y)).replace("0x", "")
                if len(y) == 1:
                    y = "0" + y
                y = self.sbox[int("0x"+y[0], 16)][int("0x"+y[1], 16)]
                time_block.append(y)
            sub_block.append(time_block)
        return sub_block

    def shift_rows(self, block):
        shift_block = [block[0]]
        for i,v in enumerate(block):
            if i > 0:
                time_table = v
                for x in range(1*i):
                    time_table.append(v[x])
                for x in range(1*i):
                    del time_table[0]
                shift_block.append(time_table)
        return shift_block

    def mix_columns(self, block):
        def xtime(ex):
            if ex & 0x80:
                ex = ex << 1
                ex ^= 0x1b
            else:
                ex = ex << 1
            return ex & 0xff
        time_block = [[], [], [], []]
        for i in range(4):
            column = [block[0][i], block[1][i], block[2][i], block[3][i]]
            all_xor = column[0] ^ column[1] ^ column[2] ^ column[3]
            rest = column[0]
            column[0] ^= xtime(column[0] ^ column[1]) ^ all_xor
            column[1] ^= xtime(column[1] ^ column[2]) ^ all_xor
            column[2] ^= xtime(column[2] ^ column[3]) ^ all_xor
            column[3] ^= xtime(column[3] ^ rest) ^ all_xor
            for si in range(4):
                time_block[si].append(column[si])
        return time_block

    def add_round_key(self, block, key):
        time_table = [[], [], [], []]
        for i in range(4):
            column = [block[0][i], block[1][i], block[2][i], block[3][i]]
            for y in range(4):
                sy = column[y] ^ key[i][y]
                time_table[y].append(sy)
        return time_table

    def encryption(self, block):
        state = self.make_state(block) 
        state = self.add_round_key(state, self.key[:4])
        for i in range(1, self.Nr):
            state = self.subbytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, self.key[(i*4):i*4+4])
        state = self.subbytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, self.key[self.Nr*self.Nb:(self.Nr+1)*self.Nb] )
        return self.return_state(state) 
    
    def inv_shift_rows(self, block):
        time_table = [block[0]]
        for i,v in enumerate(block):
            if i > 0:
                time_row = v
                for x in range(i):
                    time_row.insert(0, time_row[-(1*x)-1])
                time_table.append(time_row[:4])
        return time_table
    
    def inv_subbytes(self, block):
        time_table = [[], [], [], []]
        for i,v in enumerate(block):
            for x in v:
                sx = str(hex(x)).replace("0x", "")
                if len(sx) == 1:
                    sx = "0" + sx
                sx = self.inv_sbox[int("0x" + sx[0], 16)][int("0x" + sx[1], 16)]
                time_table[i].append(sx)
        return time_table
    
    def make_state(self, block):
        if type(block) != list and len(block) == 32:
            exit("Must be list")
        else:
            time_block = [[], [], [], []]
            for i in range(4):
                time_block[0].append(block[0 + (4 * i)])
                time_block[1].append(block[1 + (4 * i)])
                time_block[2].append(block[2 + (4 * i)])
                time_block[3].append(block[3 + (4 * i)])

            return time_block

    def return_state(self, block):
        time_block = []
        for i in range(4):
            column = [block[0][i], block[1][i], block[2][i], block[3][i]]
            for x in column:
                time_block.append(x)
        return time_block

    def inv_mixcolumn(self, block):
        def xtime(ex):
            if ex & 0x80:
                ex = ex << 1
                ex ^= 0x1b
            else:
                ex = ex << 1
            return ex & 0xff
        time_table = [[], [], [], []]
        for i in range(4):
            column = [block[0][i], block[1][i], block[2][i], block[3][i]]
            w1 = xtime(xtime(column[0] ^ column[2]))
            w2 = xtime(xtime(column[1] ^ column[3]))
            column[0] ^= w1
            column[1] ^= w2
            column[2] ^= w1
            column[3] ^= w2
            for x in range(4):
                time_table[x].append(column[x])
        return self.mix_columns(time_table) 
    
    def matrix_to_line(self, table):
        timne_text = ""
        for i in range(4):
            column = [table[0][i], table[1][i], table[2][i], table[3][i] ]
            for y in column:
                sy = str(hex(y)).replace("0x", "")
                if len(sy) == 1:
                    sy = "0" + sy
                timne_text += sy
        return timne_text

    def decryption(self, block):
        state = self.make_state(block)
        state = self.add_round_key(state, self.key[self.Nr*self.Nb:((self.Nr+1)*self.Nb-1)+1])
        for i in range(self.Nr-1, 0, -1 ):
            state = self.inv_shift_rows(state)
            state = self.inv_subbytes(state)
            state = self.add_round_key(state, self.key[i*self.Nb:((i+1)*self.Nb-1)+1] )
            state = self.inv_mixcolumn(state)
        state = self.inv_shift_rows(state)
        state = self.inv_subbytes(state)
        state = self.add_round_key(state, self.key[0:self.Nb])
        return self.return_state(state)