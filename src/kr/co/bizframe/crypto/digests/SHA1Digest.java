/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.digests;

import kr.co.bizframe.crypto.util.Pack;

/**
 * SHA-1의 구현
 */
public class SHA1Digest extends GeneralDigest {

	private static final int DIGEST_LENGTH = 20;

	private int H0, H1, H2, H3, H4;

	private int[] W = new int[80];
	private int wOff;

	/**
	 * 기본 생성자
	 */
	public SHA1Digest() {
		reset();
	}

	/**
	 * 복사 생성자
	 * 
	 * @param t 복사 대상
	 */
	public SHA1Digest(SHA1Digest t) {
		super(t);

		H0 = t.H0;
		H1 = t.H1;
		H2 = t.H2;
		H3 = t.H3;
		H4 = t.H4;

		System.arraycopy(t.W, 0, W, 0, t.W.length);
		wOff = t.wOff;
	}

	public String getAlgorithmName() {
		return "SHA-1";
	}

	public int getDigestSize() {
		return DIGEST_LENGTH;
	}

	protected void processWord(byte[] in, int inOff) {
		// Note: Inlined for performance
		// X[xOff] = Pack.bigEndianToInt(in, inOff);
		int n = in[inOff] << 24;
		n |= (in[++inOff] & 0xff) << 16;
		n |= (in[++inOff] & 0xff) << 8;
		n |= (in[++inOff] & 0xff);
		W[wOff] = n;

		if (++wOff == 16) {
			processBlock();
		}
	}

	protected void processLength(long bitLength) {
		if (wOff > 14) {
			processBlock();
		}

		W[14] = (int) (bitLength >>> 32);
		W[15] = (int) (bitLength & 0xffffffff);
	}

	public int doFinal(byte[] out, int outOff) {
		finish();

		Pack.intToBigEndian(H0, out, outOff);
		Pack.intToBigEndian(H1, out, outOff + 4);
		Pack.intToBigEndian(H2, out, outOff + 8);
		Pack.intToBigEndian(H3, out, outOff + 12);
		Pack.intToBigEndian(H4, out, outOff + 16);

		reset();

		return DIGEST_LENGTH;
	}

	/**
	 * reset the chaining variables
	 */
	public void reset() {
		super.reset();

		// 해시 초기값
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

	//
	// Additive constants
	//
	private static final int K1 = 0x5a827999;
	private static final int K2 = 0x6ed9eba1;
	private static final int K3 = 0x8f1bbcdc;
	private static final int K4 = 0xca62c1d6;

	private int Ch(int x, int y, int z) {
		return ((x & y) | ((~x) & z));
	}

	private int Parity(int x, int y, int z) {
		return (x ^ y ^ z);
	}

	private int Maj(int x, int y, int z) {
		return ((x & y) | (x & z) | (y & z));
	}

	protected void processBlock() {

		//
		// 512 비트 입력 80개의 32비트 블록으로 확장
		//
		for (int i = 16; i < 80; i++) {
			int t = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
			W[i] = t << 1 | t >>> 31;
		}

		//
		// set up working variables.
		//
		int a = H0;
		int b = H1;
		int c = H2;
		int d = H3;
		int e = H4;

		int idx = 0;

		// ////////////////////////////////////////////////////////////
		// 총 4라운드, 라운드 당 20단계
		//
		// ////////////////////////////////////////////////////////////

		//
		// round 1
		//
		// t = 0,....,19
		//
		/*
		 * for (int j = 0; j < 4; j++) { // E = rotateLeft(A, 5) + Ch(B, C, D) +
		 * E + w[idx++] + K1 // B = rotateLeft(B, 30) E += (A << 5 | A >>> 27) +
		 * Ch(B, C, D) + w[idx++] + K1; B = B << 30 | B >>> 2;
		 * 
		 * D += (E << 5 | E >>> 27) + Ch(A, B, C) + w[idx++] + K1; A = A << 30 |
		 * A >>> 2;
		 * 
		 * C += (D << 5 | D >>> 27) + Ch(E, A, B) + w[idx++] + K1; E = E << 30 |
		 * E >>> 2;
		 * 
		 * B += (C << 5 | C >>> 27) + Ch(D, E, A) + w[idx++] + K1; D = D << 30 |
		 * D >>> 2;
		 * 
		 * A += (B << 5 | B >>> 27) + Ch(C, D, E) + w[idx++] + K1; C = C << 30 |
		 * C >>> 2; }
		 */

		for (int t = 0; t < 20; t++) {
			int T = (a << 5 | a >>> 27) + Ch(b, c, d) + e + W[idx++] + K1;
			e = d;
			d = c;
			c = (b << 30 | b >>> 2);
			b = a;
			a = T;
		}

		//
		// round 2
		//
		// t =20,...,39
		//
		/*
		 * for (int j = 0; j < 4; j++) { // E = rotateLeft(A, 5) + h(B, C, D) +
		 * E + w[idx++] + K2 // B = rotateLeft(B, 30) E += (A << 5 | A >>> 27) +
		 * Parity(B, C, D) + w[idx++] + K2; B = B << 30 | B >>> 2;
		 * 
		 * D += (E << 5 | E >>> 27) + Parity(A, B, C) + w[idx++] + K2; A = A <<
		 * 30 | A >>> 2;
		 * 
		 * C += (D << 5 | D >>> 27) + Parity(E, A, B) + w[idx++] + K2; E = E <<
		 * 30 | E >>> 2;
		 * 
		 * B += (C << 5 | C >>> 27) + Parity(D, E, A) + w[idx++] + K2; D = D <<
		 * 30 | D >>> 2;
		 * 
		 * A += (B << 5 | B >>> 27) + Parity(C, D, E) + w[idx++] + K2; C = C <<
		 * 30 | C >>> 2; }
		 */

		for (int t = 20; t < 40; t++) {
			int T = (a << 5 | a >>> 27) + Parity(b, c, d) + e + W[idx++] + K2;
			e = d;
			d = c;
			c = (b << 30 | b >>> 2);
			b = a;
			a = T;
		}

		//
		// round 3
		//
		// t=40,....,59
		//
		/*
		 * for (int j = 0; j < 4; j++) { // E = rotateLeft(A, 5) + g(B, C, D) +
		 * E + w[idx++] + K3 // B = rotateLeft(B, 30) E += (A << 5 | A >>> 27) +
		 * Maj(B, C, D) + w[idx++] + K3; B = B << 30 | B >>> 2;
		 * 
		 * D += (E << 5 | E >>> 27) + Maj(A, B, C) + w[idx++] + K3; A = A << 30
		 * | A >>> 2;
		 * 
		 * C += (D << 5 | D >>> 27) + Maj(E, A, B) + w[idx++] + K3; E = E << 30
		 * | E >>> 2;
		 * 
		 * B += (C << 5 | C >>> 27) + Maj(D, E, A) + w[idx++] + K3; D = D << 30
		 * | D >>> 2;
		 * 
		 * A += (B << 5 | B >>> 27) + Maj(C, D, E) + w[idx++] + K3; C = C << 30
		 * | C >>> 2; }
		 */
		for (int t = 40; t < 60; t++) {
			int temp = (a << 5 | a >>> 27) + Maj(b, c, d) + e + W[idx++] + K3;
			e = d;
			d = c;
			c = (b << 30 | b >>> 2);
			b = a;
			a = temp;
		}

		//
		// round 4
		//
		// t=60,.....,79
		//
		/*
		 * for (int j = 0; j < 4; j++) { // E = rotateLeft(A, 5) + h(B, C, D) +
		 * E + w[idx++] + K4 // B = rotateLeft(B, 30) E += (A << 5 | A >>> 27) +
		 * Parity(B, C, D) + w[idx++] + K4; B = B << 30 | B >>> 2;
		 * 
		 * D += (E << 5 | E >>> 27) + Parity(A, B, C) + w[idx++] + K4; A = A <<
		 * 30 | A >>> 2;
		 * 
		 * C += (D << 5 | D >>> 27) + Parity(E, A, B) + w[idx++] + K4; E = E <<
		 * 30 | E >>> 2;
		 * 
		 * B += (C << 5 | C >>> 27) + Parity(D, E, A) + w[idx++] + K4; D = D <<
		 * 30 | D >>> 2;
		 * 
		 * A += (B << 5 | B >>> 27) + Parity(C, D, E) + w[idx++] + K4; C = C <<
		 * 30 | C >>> 2; }
		 */

		for (int t = 60; t < 80; t++) {
			int T = (a << 5 | a >>> 27) + Parity(b, c, d) + e + W[idx++] + K4;
			e = d;
			d = c;
			c = (b << 30 | b >>> 2);
			b = a;
			a = T;
		}

		H0 += a;
		H1 += b;
		H2 += c;
		H3 += d;
		H4 += e;

		//
		// reset start of the buffer.
		//
		wOff = 0;
		for (int i = 0; i < 16; i++) {
			W[i] = 0;
		}
	}
}
