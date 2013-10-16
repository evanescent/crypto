package kr.co.bizframe.crypto.ciphers;

import kr.co.bizframe.crypto.BlockCipher;
import kr.co.bizframe.crypto.CipherParameters;
import kr.co.bizframe.crypto.DataLengthException;
import kr.co.bizframe.crypto.params.KeyParameter;
import kr.co.bizframe.crypto.util.ByteUtil;

public class HIGHTEngine implements BlockCipher {

	private static final int BLOCK_SIZE = 8;

	private static final int SUBKEY_SIZE = 128;

	private boolean encrypting = false;

    private byte[] MK = null; // Master Key

    private byte[] WK = new byte[BLOCK_SIZE]; // Whitening Key

    private byte[] SK = new byte[SUBKEY_SIZE]; // Subkey

    private final static byte[] Delta = {
    	(byte) 0x5a, (byte) 0x6d, (byte) 0x36, (byte) 0x1b, (byte) 0x0d, (byte) 0x06, (byte) 0x03, (byte) 0x41,
    	(byte) 0x60, (byte) 0x30, (byte) 0x18, (byte) 0x4c,	(byte) 0x66, (byte) 0x33, (byte) 0x59, (byte) 0x2c,
    	(byte) 0x56, (byte) 0x2b, (byte) 0x15, (byte) 0x4a,	(byte) 0x65, (byte) 0x72, (byte) 0x39, (byte) 0x1c,
    	(byte) 0x4e, (byte) 0x67, (byte) 0x73, (byte) 0x79,	(byte) 0x3c, (byte) 0x5e, (byte) 0x6f, (byte) 0x37,
    	(byte) 0x5b, (byte) 0x2d, (byte) 0x16, (byte) 0x0b,	(byte) 0x05, (byte) 0x42, (byte) 0x21, (byte) 0x50,
    	(byte) 0x28, (byte) 0x54, (byte) 0x2a, (byte) 0x55,	(byte) 0x6a, (byte) 0x75, (byte) 0x7a, (byte) 0x7d,
    	(byte) 0x3e, (byte) 0x5f, (byte) 0x2f, (byte) 0x17,	(byte) 0x4b, (byte) 0x25, (byte) 0x52, (byte) 0x29,
    	(byte) 0x14, (byte) 0x0a, (byte) 0x45, (byte) 0x62,	(byte) 0x31, (byte) 0x58, (byte) 0x6c, (byte) 0x76,
    	(byte) 0x3b, (byte) 0x1d, (byte) 0x0e, (byte) 0x47,	(byte) 0x63, (byte) 0x71, (byte) 0x78, (byte) 0x7c,
    	(byte) 0x7e, (byte) 0x7f, (byte) 0x3f, (byte) 0x1f,	(byte) 0x0f, (byte) 0x07, (byte) 0x43, (byte) 0x61,
    	(byte) 0x70, (byte) 0x38, (byte) 0x5c, (byte) 0x6e,	(byte) 0x77, (byte) 0x7b, (byte) 0x3d, (byte) 0x1e,
    	(byte) 0x4f, (byte) 0x27, (byte) 0x53, (byte) 0x69,	(byte) 0x34, (byte) 0x1a, (byte) 0x4d, (byte) 0x26,
    	(byte) 0x13, (byte) 0x49, (byte) 0x24, (byte) 0x12,	(byte) 0x09, (byte) 0x04, (byte) 0x02, (byte) 0x01,
    	(byte) 0x40, (byte) 0x20, (byte) 0x10, (byte) 0x08,	(byte) 0x44, (byte) 0x22, (byte) 0x11, (byte) 0x48,
    	(byte) 0x64, (byte) 0x32, (byte) 0x19, (byte) 0x0c,	(byte) 0x46, (byte) 0x23, (byte) 0x51, (byte) 0x68,
    	(byte) 0x74, (byte) 0x3a, (byte) 0x5d, (byte) 0x2e,	(byte) 0x57, (byte) 0x6b, (byte) 0x35, (byte) 0x5a
    };

    private final static byte[] F0 = {
        (byte) 0x00, (byte) 0x86, (byte) 0x0d, (byte) 0x8b, (byte) 0x1a, (byte) 0x9c, (byte) 0x17, (byte) 0x91,
        (byte) 0x34, (byte) 0xb2, (byte) 0x39, (byte) 0xbf, (byte) 0x2e, (byte) 0xa8, (byte) 0x23, (byte) 0xa5,
        (byte) 0x68, (byte) 0xee, (byte) 0x65, (byte) 0xe3, (byte) 0x72, (byte) 0xf4, (byte) 0x7f, (byte) 0xf9,
        (byte) 0x5c, (byte) 0xda, (byte) 0x51, (byte) 0xd7, (byte) 0x46, (byte) 0xc0, (byte) 0x4b, (byte) 0xcd,
        (byte) 0xd0, (byte) 0x56, (byte) 0xdd, (byte) 0x5b, (byte) 0xca, (byte) 0x4c, (byte) 0xc7, (byte) 0x41,
        (byte) 0xe4, (byte) 0x62, (byte) 0xe9, (byte) 0x6f, (byte) 0xfe, (byte) 0x78, (byte) 0xf3, (byte) 0x75,
        (byte) 0xb8, (byte) 0x3e, (byte) 0xb5, (byte) 0x33, (byte) 0xa2, (byte) 0x24, (byte) 0xaf, (byte) 0x29,
        (byte) 0x8c, (byte) 0x0a, (byte) 0x81, (byte) 0x07, (byte) 0x96, (byte) 0x10, (byte) 0x9b, (byte) 0x1d,
        (byte) 0xa1, (byte) 0x27, (byte) 0xac, (byte) 0x2a, (byte) 0xbb, (byte) 0x3d, (byte) 0xb6, (byte) 0x30,
        (byte) 0x95, (byte) 0x13, (byte) 0x98, (byte) 0x1e, (byte) 0x8f, (byte) 0x09, (byte) 0x82, (byte) 0x04,
        (byte) 0xc9, (byte) 0x4f, (byte) 0xc4, (byte) 0x42, (byte) 0xd3, (byte) 0x55, (byte) 0xde, (byte) 0x58,
        (byte) 0xfd, (byte) 0x7b, (byte) 0xf0, (byte) 0x76, (byte) 0xe7, (byte) 0x61, (byte) 0xea, (byte) 0x6c,
        (byte) 0x71, (byte) 0xf7, (byte) 0x7c, (byte) 0xfa, (byte) 0x6b, (byte) 0xed, (byte) 0x66, (byte) 0xe0,
        (byte) 0x45, (byte) 0xc3, (byte) 0x48, (byte) 0xce, (byte) 0x5f, (byte) 0xd9, (byte) 0x52, (byte) 0xd4,
        (byte) 0x19, (byte) 0x9f, (byte) 0x14, (byte) 0x92, (byte) 0x03, (byte) 0x85, (byte) 0x0e, (byte) 0x88,
        (byte) 0x2d, (byte) 0xab, (byte) 0x20, (byte) 0xa6, (byte) 0x37, (byte) 0xb1, (byte) 0x3a, (byte) 0xbc,
        (byte) 0x43, (byte) 0xc5, (byte) 0x4e, (byte) 0xc8, (byte) 0x59, (byte) 0xdf, (byte) 0x54, (byte) 0xd2,
        (byte) 0x77, (byte) 0xf1, (byte) 0x7a, (byte) 0xfc, (byte) 0x6d, (byte) 0xeb, (byte) 0x60, (byte) 0xe6,
        (byte) 0x2b, (byte) 0xad, (byte) 0x26, (byte) 0xa0, (byte) 0x31, (byte) 0xb7, (byte) 0x3c, (byte) 0xba,
        (byte) 0x1f, (byte) 0x99, (byte) 0x12, (byte) 0x94, (byte) 0x05, (byte) 0x83, (byte) 0x08, (byte) 0x8e,
        (byte) 0x93, (byte) 0x15, (byte) 0x9e, (byte) 0x18, (byte) 0x89, (byte) 0x0f, (byte) 0x84, (byte) 0x02,
        (byte) 0xa7, (byte) 0x21, (byte) 0xaa, (byte) 0x2c, (byte) 0xbd, (byte) 0x3b, (byte) 0xb0, (byte) 0x36,
        (byte) 0xfb, (byte) 0x7d, (byte) 0xf6, (byte) 0x70, (byte) 0xe1, (byte) 0x67, (byte) 0xec, (byte) 0x6a,
        (byte) 0xcf, (byte) 0x49, (byte) 0xc2, (byte) 0x44, (byte) 0xd5, (byte) 0x53, (byte) 0xd8, (byte) 0x5e,
        (byte) 0xe2, (byte) 0x64, (byte) 0xef, (byte) 0x69, (byte) 0xf8, (byte) 0x7e, (byte) 0xf5, (byte) 0x73,
        (byte) 0xd6, (byte) 0x50, (byte) 0xdb, (byte) 0x5d, (byte) 0xcc, (byte) 0x4a, (byte) 0xc1, (byte) 0x47,
        (byte) 0x8a, (byte) 0x0c, (byte) 0x87, (byte) 0x01, (byte) 0x90, (byte) 0x16, (byte) 0x9d, (byte) 0x1b,
        (byte) 0xbe, (byte) 0x38, (byte) 0xb3, (byte) 0x35, (byte) 0xa4, (byte) 0x22, (byte) 0xa9, (byte) 0x2f,
        (byte) 0x32, (byte) 0xb4, (byte) 0x3f, (byte) 0xb9, (byte) 0x28, (byte) 0xae, (byte) 0x25, (byte) 0xa3,
        (byte) 0x06, (byte) 0x80, (byte) 0x0b, (byte) 0x8d, (byte) 0x1c, (byte) 0x9a, (byte) 0x11, (byte) 0x97,
        (byte) 0x5a, (byte) 0xdc, (byte) 0x57, (byte) 0xd1, (byte) 0x40, (byte) 0xc6, (byte) 0x4d, (byte) 0xcb,
        (byte) 0x6e, (byte) 0xe8, (byte) 0x63, (byte) 0xe5, (byte) 0x74, (byte) 0xf2, (byte) 0x79, (byte) 0xff
    };

    private static final byte[] F1 = {
        (byte) 0x00, (byte) 0x58, (byte) 0xb0, (byte) 0xe8, (byte) 0x61, (byte) 0x39, (byte) 0xd1, (byte) 0x89,
        (byte) 0xc2, (byte) 0x9a, (byte) 0x72, (byte) 0x2a, (byte) 0xa3, (byte) 0xfb, (byte) 0x13, (byte) 0x4b,
        (byte) 0x85, (byte) 0xdd, (byte) 0x35, (byte) 0x6d, (byte) 0xe4, (byte) 0xbc, (byte) 0x54, (byte) 0x0c,
        (byte) 0x47, (byte) 0x1f, (byte) 0xf7, (byte) 0xaf, (byte) 0x26, (byte) 0x7e, (byte) 0x96, (byte) 0xce,
        (byte) 0x0b, (byte) 0x53, (byte) 0xbb, (byte) 0xe3, (byte) 0x6a, (byte) 0x32, (byte) 0xda, (byte) 0x82,
        (byte) 0xc9, (byte) 0x91, (byte) 0x79, (byte) 0x21, (byte) 0xa8, (byte) 0xf0, (byte) 0x18, (byte) 0x40,
        (byte) 0x8e, (byte) 0xd6, (byte) 0x3e, (byte) 0x66, (byte) 0xef, (byte) 0xb7, (byte) 0x5f, (byte) 0x07,
        (byte) 0x4c, (byte) 0x14, (byte) 0xfc, (byte) 0xa4, (byte) 0x2d, (byte) 0x75, (byte) 0x9d, (byte) 0xc5,
        (byte) 0x16, (byte) 0x4e, (byte) 0xa6, (byte) 0xfe, (byte) 0x77, (byte) 0x2f, (byte) 0xc7, (byte) 0x9f,
        (byte) 0xd4, (byte) 0x8c, (byte) 0x64, (byte) 0x3c, (byte) 0xb5, (byte) 0xed, (byte) 0x05, (byte) 0x5d,
        (byte) 0x93, (byte) 0xcb, (byte) 0x23, (byte) 0x7b, (byte) 0xf2, (byte) 0xaa, (byte) 0x42, (byte) 0x1a,
        (byte) 0x51, (byte) 0x09, (byte) 0xe1, (byte) 0xb9, (byte) 0x30, (byte) 0x68, (byte) 0x80, (byte) 0xd8,
        (byte) 0x1d, (byte) 0x45, (byte) 0xad, (byte) 0xf5, (byte) 0x7c, (byte) 0x24, (byte) 0xcc, (byte) 0x94,
        (byte) 0xdf, (byte) 0x87, (byte) 0x6f, (byte) 0x37, (byte) 0xbe, (byte) 0xe6, (byte) 0x0e, (byte) 0x56,
        (byte) 0x98, (byte) 0xc0, (byte) 0x28, (byte) 0x70, (byte) 0xf9, (byte) 0xa1, (byte) 0x49, (byte) 0x11,
        (byte) 0x5a, (byte) 0x02, (byte) 0xea, (byte) 0xb2, (byte) 0x3b, (byte) 0x63, (byte) 0x8b, (byte) 0xd3,
        (byte) 0x2c, (byte) 0x74, (byte) 0x9c, (byte) 0xc4, (byte) 0x4d, (byte) 0x15, (byte) 0xfd, (byte) 0xa5,
        (byte) 0xee, (byte) 0xb6, (byte) 0x5e, (byte) 0x06, (byte) 0x8f, (byte) 0xd7, (byte) 0x3f, (byte) 0x67,
        (byte) 0xa9, (byte) 0xf1, (byte) 0x19, (byte) 0x41, (byte) 0xc8, (byte) 0x90, (byte) 0x78, (byte) 0x20,
        (byte) 0x6b, (byte) 0x33, (byte) 0xdb, (byte) 0x83, (byte) 0x0a, (byte) 0x52, (byte) 0xba, (byte) 0xe2,
        (byte) 0x27, (byte) 0x7f, (byte) 0x97, (byte) 0xcf, (byte) 0x46, (byte) 0x1e, (byte) 0xf6, (byte) 0xae,
        (byte) 0xe5, (byte) 0xbd, (byte) 0x55, (byte) 0x0d, (byte) 0x84, (byte) 0xdc, (byte) 0x34, (byte) 0x6c,
        (byte) 0xa2, (byte) 0xfa, (byte) 0x12, (byte) 0x4a, (byte) 0xc3, (byte) 0x9b, (byte) 0x73, (byte) 0x2b,
        (byte) 0x60, (byte) 0x38, (byte) 0xd0, (byte) 0x88, (byte) 0x01, (byte) 0x59, (byte) 0xb1, (byte) 0xe9,
        (byte) 0x3a, (byte) 0x62, (byte) 0x8a, (byte) 0xd2, (byte) 0x5b, (byte) 0x03, (byte) 0xeb, (byte) 0xb3,
        (byte) 0xf8, (byte) 0xa0, (byte) 0x48, (byte) 0x10, (byte) 0x99, (byte) 0xc1, (byte) 0x29, (byte) 0x71,
        (byte) 0xbf, (byte) 0xe7, (byte) 0x0f, (byte) 0x57, (byte) 0xde, (byte) 0x86, (byte) 0x6e, (byte) 0x36,
        (byte) 0x7d, (byte) 0x25, (byte) 0xcd, (byte) 0x95, (byte) 0x1c, (byte) 0x44, (byte) 0xac, (byte) 0xf4,
        (byte) 0x31, (byte) 0x69, (byte) 0x81, (byte) 0xd9, (byte) 0x50, (byte) 0x08, (byte) 0xe0, (byte) 0xb8,
        (byte) 0xf3, (byte) 0xab, (byte) 0x43, (byte) 0x1b, (byte) 0x92, (byte) 0xca, (byte) 0x22, (byte) 0x7a,
        (byte) 0xb4, (byte) 0xec, (byte) 0x04, (byte) 0x5c, (byte) 0xd5, (byte) 0x8d, (byte) 0x65, (byte) 0x3d,
        (byte) 0x76, (byte) 0x2e, (byte) 0xc6, (byte) 0x9e, (byte) 0x17, (byte) 0x4f, (byte) 0xa7, (byte) 0xff
    };

	/**
	 * default constructor - 64 bit block size.
	 */
	public HIGHTEngine() {
	}

	public String getAlgorithmName() {
		return "HIGHT";
	}

	public int getBlockSize() {
		return BLOCK_SIZE;
	}

	public void init(boolean forEncryption, CipherParameters params)
			throws IllegalArgumentException {
		if (params instanceof KeyParameter)
        {
            this.encrypting = forEncryption;
            this.MK = ((KeyParameter)params).getKey();
            setKey();

            return;
        }

        throw new IllegalArgumentException("invalid parameter passed to HIGHT init - " + params.getClass().getName());
	}

	public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
			throws DataLengthException, IllegalStateException {
		if (MK == null)
        {
            throw new IllegalStateException("HIGHT not initialised");
        }

        if ((inOff + BLOCK_SIZE) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if ((outOff + BLOCK_SIZE) > out.length)
        {
            throw new DataLengthException("output buffer too short");
        }

        if (encrypting)
        {
            encryptBlock(in, inOff, out, outOff);
        }
        else
        {
            decryptBlock(in, inOff, out, outOff);
        }

        return BLOCK_SIZE;
	}

	public void reset() {
	}

	private void setKey()
    {
		for(int i = 0; i < 4; i++) {
			WK[i] = MK[i + 12];
			WK[i + 4] = MK[i];
		}

		int idx;
		for(int i = 0; i < 8; i++) {
			for(int j = 0; j < 8; j++) {
				idx = 16 * i + j;
				SK[idx] = (byte) (MK[(j - i) & 7] + Delta[idx]);
			}
			for(int j = 0; j < 8; j++) {
				idx = 16 * i + j + 8;
				SK[idx] = (byte) (MK[((j - i) & 7) + 8] + Delta[idx]);
			}
		}
    }

	private void encryptBlock(
	        byte[]  src,
	        int     srcIndex,
	        byte[]  dst,
	        int     dstIndex)
    {
	    // First Round
		dst[dstIndex + 1] = src[srcIndex + 1];
		dst[dstIndex + 3] = src[srcIndex + 3];
		dst[dstIndex + 5] = src[srcIndex + 5];
		dst[dstIndex + 7] = src[srcIndex + 7];

		dst[dstIndex + 0] = (byte) (src[srcIndex + 0] + WK[0]);
		dst[dstIndex + 2] = (byte) (src[srcIndex + 2] ^ WK[1]);
		dst[dstIndex + 4] = (byte) (src[srcIndex + 4] + WK[2]);
		dst[dstIndex + 6] = (byte) (src[srcIndex + 6] ^ WK[3]);

		byte[] next = new byte[BLOCK_SIZE];
		for (int i = 0; i < 32; i++) {
			if (i != 31) {
				next[0] = (byte) (dst[dstIndex + 7] ^ (F0[dst[dstIndex + 6] & 0xff] + SK[4 * i + 3]));
				next[1] = dst[dstIndex + 0];
				next[2] = (byte) (dst[dstIndex + 1] + (F1[dst[dstIndex + 0] & 0xff] ^ SK[4 * i + 0]));
				next[3] = dst[dstIndex + 2];
				next[4] = (byte) (dst[dstIndex + 3] ^ (F0[dst[dstIndex + 2] & 0xff] + SK[4 * i + 1]));
				next[5] = dst[dstIndex + 4];
				next[6] = (byte) (dst[dstIndex + 5] + (F1[dst[dstIndex + 4] & 0xff] ^ SK[4 * i + 2]));
				next[7] = dst[dstIndex + 6];
			} else {
				next[1] = (byte) (dst[dstIndex + 1] + (F1[dst[dstIndex + 0] & 0xff] ^ SK[124]));
				next[3] = (byte) (dst[dstIndex + 3] ^ (F0[dst[dstIndex + 2] & 0xff] + SK[125]));
				next[5] = (byte) (dst[dstIndex + 5] + (F1[dst[dstIndex + 4] & 0xff] ^ SK[126]));
				next[7] = (byte) (dst[dstIndex + 7] ^ (F0[dst[dstIndex + 6] & 0xff] + SK[127]));
				next[0] = dst[dstIndex + 0];
				next[2] = dst[dstIndex + 2];
				next[4] = dst[dstIndex + 4];
				next[6] = dst[dstIndex + 6];
			}

			System.arraycopy(next, 0, dst, dstIndex, BLOCK_SIZE);
		}

	    // Final Round
		dst[dstIndex + 1] = (byte) dst[dstIndex + 1];
	    dst[dstIndex + 3] = (byte) dst[dstIndex + 3];
	    dst[dstIndex + 5] = (byte) dst[dstIndex + 5];
	    dst[dstIndex + 7] = (byte) dst[dstIndex + 7];

	    dst[dstIndex + 0] = (byte) (dst[dstIndex + 0] + WK[4]);
	    dst[dstIndex + 2] = (byte) (dst[dstIndex + 2] ^ WK[5]);
	    dst[dstIndex + 4] = (byte) (dst[dstIndex + 4] + WK[6]);
	    dst[dstIndex + 6] = (byte) (dst[dstIndex + 6] ^ WK[7]);
    }

	private void decryptBlock(
	        byte[] src,
	        int srcIndex,
	        byte[] dst,
	        int dstIndex)
    {
		// First Round
		dst[dstIndex + 1] = src[srcIndex + 1];
		dst[dstIndex + 3] = src[srcIndex + 3];
		dst[dstIndex + 5] = src[srcIndex + 5];
		dst[dstIndex + 7] = src[srcIndex + 7];

		dst[dstIndex + 0] = (byte) (src[srcIndex + 0] - WK[4]);
		dst[dstIndex + 2] = (byte) (src[srcIndex + 2] ^ WK[5]);
		dst[dstIndex + 4] = (byte) (src[srcIndex + 4] - WK[6]);
		dst[dstIndex + 6] = (byte) (src[srcIndex + 6] ^ WK[7]);

		byte[] next = new byte[BLOCK_SIZE];
		for (int i = 0; i < 32; i++) {
			if (i != 31) {
				next[0] = (byte) (dst[dstIndex + 1] - (F1[dst[dstIndex + 0] & 0xff] ^ SK[127 - (4 * i + 3)]));
				next[1] = dst[dstIndex + 2];
				next[2] = (byte) (dst[dstIndex + 3] ^ (F0[dst[dstIndex + 2] & 0xff] + SK[127 - (4 * i + 2)]));
				next[3] = dst[dstIndex + 4];
				next[4] = (byte) (dst[dstIndex + 5] - (F1[dst[dstIndex + 4] & 0xff] ^ SK[127 - (4 * i + 1)]));
				next[5] = dst[dstIndex + 6];
				next[6] = (byte) (dst[dstIndex + 7] ^ (F0[dst[dstIndex + 6] & 0xff] + SK[127 - (4 * i + 0)]));
				next[7] = dst[dstIndex + 0];
			} else {
				next[1] = (byte) (dst[dstIndex + 1] - (F1[dst[dstIndex + 0] & 0xff] ^ SK[0]));
				next[3] = (byte) (dst[dstIndex + 3] ^ (F0[dst[dstIndex + 2] & 0xff] + SK[1]));
				next[5] = (byte) (dst[dstIndex + 5] - (F1[dst[dstIndex + 4] & 0xff] ^ SK[2]));
				next[7] = (byte) (dst[dstIndex + 7] ^ (F0[dst[dstIndex + 6] & 0xff] + SK[3]));
				next[0] = dst[dstIndex + 0];
				next[2] = dst[dstIndex + 2];
				next[4] = dst[dstIndex + 4];
				next[6] = dst[dstIndex + 6];
			}
			System.arraycopy(next, 0, dst, dstIndex, BLOCK_SIZE);
		}

	    // Final Round
		dst[dstIndex + 1] = (byte) dst[dstIndex + 1];
	    dst[dstIndex + 3] = (byte) dst[dstIndex + 3];
	    dst[dstIndex + 5] = (byte) dst[dstIndex + 5];
	    dst[dstIndex + 7] = (byte) dst[dstIndex + 7];

	    dst[dstIndex + 0] = (byte) (dst[dstIndex + 0] - WK[0]);
	    dst[dstIndex + 2] = (byte) (dst[dstIndex + 2] ^ WK[1]);
	    dst[dstIndex + 4] = (byte) (dst[dstIndex + 4] - WK[2]);
	    dst[dstIndex + 6] = (byte) (dst[dstIndex + 6] ^ WK[3]);
    }

	public static void main(String[] args) {

//		byte[] key = new byte [] { (byte) 0xff, (byte) 0xee, (byte) 0xdd, (byte) 0xcc, (byte) 0xbb, (byte) 0xaa, (byte) 0x99, (byte) 0x88, (byte) 0x77, (byte) 0x66, (byte) 0x55, (byte) 0x44, (byte) 0x33, (byte) 0x22, (byte) 0x11, (byte) 0x00 };
//		byte[] p = new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };

		//byte[] key = new byte [] { (byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff };
		//byte[] p = new byte[] { (byte) 0x77, (byte) 0x66, (byte) 0x55, (byte) 0x44, (byte) 0x33, (byte) 0x22,(byte) 0x11, (byte) 0x00 };

		byte[] key = { (byte) 0x0f, (byte) 0x0e, (byte) 0x0d, (byte) 0x0c, (byte) 0x0b, (byte) 0x0a, (byte) 0x09, (byte) 0x08, (byte) 0x07, (byte) 0x06, (byte) 0x05, (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x01, (byte) 0x00 };
		byte[] p = { (byte) 0xef, (byte) 0xcd, (byte) 0xab, (byte) 0x89, (byte) 0x67, (byte) 0x45, (byte) 0x23, (byte) 0x01 };

//		byte[] key = { (byte) 0xe7, (byte) 0x2b, (byte) 0x42, (byte) 0x1d, (byte) 0xb1, (byte) 0x09, (byte) 0xa5, (byte) 0xcf, (byte) 0x7d, (byte) 0xd8, (byte) 0xff, (byte) 0x49, (byte) 0xbc, (byte) 0xc3, (byte) 0xdb, (byte) 0x28 };
//		byte[] p = { (byte) 0x14,(byte) 0x4a,(byte) 0xa8,(byte) 0xeb,(byte) 0xe2,(byte) 0x6b,(byte) 0x1e,(byte) 0xb4 };


		System.out.println(toHexString(key));
		System.out.println(ByteUtil.toHexString(key));

		HIGHTEngine e = new HIGHTEngine();
		e.MK = key;
		e.setKey();
		byte[] c = new byte[8];
		e.encryptBlock(p, 0, c, 0);
		System.out.println(toHexString(c));

		e.MK = key;
		e.setKey();
		byte[] d = new byte[8];
		e.decryptBlock(c, 0, d, 0);
		System.out.println(toHexString(d));
	}

	public static String HEX = "0123456789abcdef";

	public static String toHexString(byte[] b) {
		StringBuffer sb = new StringBuffer();

		for(int i = b.length - 1; i >= 0; i--) {
			sb.append( HEX.charAt( (b[i] >> 4) & 0x0f ) );
			sb.append( HEX.charAt( (b[i]) & 0x0f ) );
		}

		return sb.toString();
	}
}
