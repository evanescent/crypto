/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.digests;

/**
 * 
 */
public class HAS160Digest extends GeneralDigest {

	private static final int DIGEST_LENGTH = 20;
	private int H0, H1, H2, H3, H4;
	private int[] W = new int[20];
	private int wOff;

	/**
	 * Standard constructor
	 */
	public HAS160Digest() {
		reset();
	}

	/**
	 * Copy constructor. This will copy the state of the provided message
	 * digest.
	 */
	public HAS160Digest(HAS160Digest t) {
		super(t);

		H0 = t.H0;
		H1 = t.H1;
		H2 = t.H2;
		H3 = t.H3;
		H4 = t.H4;

		System.arraycopy(t.W, 0, W, 0, t.W.length);
		wOff = t.wOff;
	}

	protected void processLength(long bitLength) {
		if (wOff > 14) {
			processBlock();
		}

		W[14] = (int) (bitLength & 0xffffffff);
		W[15] = (int) (bitLength >>> 32);
	}

	// HAS-160 uses "Little endian".
	protected void processWord(byte[] in, int inOff) {
		W[wOff++] =
			(in[inOff] & 0xff) | ((in[inOff + 1] & 0xff) << 8) |
			((in[inOff + 2] & 0xff) << 16) |
			((in[inOff + 3] & 0xff) << 24);

		if (wOff == 16) {
			processBlock();
		}
	}

	// HAS-160 uses "Little endian".
	private void unpackWord(int word, byte[] out, int outOff) {
		out[outOff++] = (byte) word;
		out[outOff++] = (byte) (word >>> 8);
		out[outOff++] = (byte) (word >>> 16);
		out[outOff++] = (byte) (word >>> 24);
	}

	public int doFinal(byte[] out, int outOff) {
		finish();

		unpackWord(H0, out, outOff);
		unpackWord(H1, out, outOff + 4);
		unpackWord(H2, out, outOff + 8);
		unpackWord(H3, out, outOff + 12);
		unpackWord(H4, out, outOff + 16);

		reset();

		return DIGEST_LENGTH;
	}

	public String getAlgorithmName() {
		return "HAS-160";
	}

	public int getDigestSize() {
		return DIGEST_LENGTH;
	}

	public void reset() {
		super.reset();

		H0 = 0x67452301;
		H1 = 0xefcdab89;
		H2 = 0x98badcfe;
		H3 = 0x10325476;
		H4 = 0xc3d2e1f0;

		wOff = 0;
		for (int i = 0; i != W.length; i++) {
			W[i] = 0;
		}
	}

	private static final int k1 = 0x00000000;
	private static final int k2 = 0x5a827999;
	private static final int k3 = 0x6ed9eba1;
	private static final int k4 = 0x8f1bbcdc;

	private static final int[] l1 = {
		18, 0, 1, 2, 3, 19, 4, 5, 6, 7,
		16, 8, 9, 10, 11, 17, 12, 13, 14, 15
	};

	private static final int[] l2 = {
		18, 3, 6, 9, 12, 19, 15, 2, 5, 8,
		16, 11, 14, 1, 4, 17, 7, 10, 13, 0
	};

	private static final int[] l3 = {
		18, 12, 5, 14, 7, 19, 0, 9, 2, 11,
		16, 4, 13, 6, 15, 17, 8, 1, 10, 3
	};

	private static final int[] l4 = {
		18, 7, 2, 13, 8, 19, 3, 14, 9, 4,
		16, 15, 10, 5, 0, 17, 11, 6, 1, 12
	};

	private static final int[] s1 = {
		5, 11, 7, 15, 6, 13, 8, 14, 7, 12,
		9, 11, 8, 15, 6, 12, 9, 14, 5, 13
	};

	private static final int[] s2 = {
		10, 17, 25, 30
	};

	private int f1(int x, int y, int z) {
		return ((x & y) | ((~x) & z));
	}

	private int f2(int x, int y, int z) {
		return (x ^ y ^ z);
	}

	private int f3(int x, int y, int z) {
		return (y ^ (x | (~z)));
	}

	// circular left shift.
	private int ROTL(int x, int n) {
		return ((x << n) | (x >>> (32 - n)));
	}

	protected void processBlock() {
		int a = H0, b = H1, c = H2, d = H3, e = H4, t;

		// round 1
		prepareX(l1);
		for (int j = 0; j < 20; j++) {
			t = ROTL(a, s1[j]) + f1(b, c, d) + e + W[l1[j]] + k1;
			e = d;
			d = c;
			c = ROTL(b, s2[0]);
			b = a;
			a = t;
		}

		// round 2
		prepareX(l2);
		for (int j = 0; j < 20; j++) {
			t = ROTL(a, s1[j]) + f2(b, c, d) + e + W[l2[j]] + k2;
			e = d;
			d = c;
			c = ROTL(b, s2[1]);
			b = a;
			a = t;
		}

		// round 3
		prepareX(l3);
		for (int j = 0; j < 20; j++) {
			t = ROTL(a, s1[j]) + f3(b, c, d) + e + W[l3[j]] + k3;
			e = d;
			d = c;
			c = ROTL(b, s2[2]);
			b = a;
			a = t;
		}

		// round 4
		prepareX(l4);
		for (int j = 0; j < 20; j++) {
			t = ROTL(a, s1[j]) + f2(b, c, d) + e + W[l4[j]] + k4;
			e = d;
			d = c;
			c = ROTL(b, s2[3]);
			b = a;
			a = t;
		}

		H0 += a;
		H1 += b;
		H2 += c;
		H3 += d;
		H4 += e;

		wOff = 0;
		for (int i = 0; i != 16; i++) {
			W[i] = 0;
		}
	}

	private void prepareX(int[] l) {
		W[16] = W[l[1]] ^ W[l[2]] ^ W[l[3]] ^ W[l[4]];
		W[17] = W[l[6]] ^ W[l[7]] ^ W[l[8]] ^ W[l[9]];
		W[18] = W[l[11]] ^ W[l[12]] ^ W[l[13]] ^ W[l[14]];
		W[19] = W[l[16]] ^ W[l[17]] ^ W[l[18]] ^ W[l[19]];
	}

}
