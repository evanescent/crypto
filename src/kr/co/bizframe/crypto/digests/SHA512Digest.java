/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.digests;

import kr.co.bizframe.crypto.util.Pack;

/**
 * FIPS 180-2, SHA-512의 구현.
 *
 * <pre>
 *         block  word  digest
 * SHA-1   512    32    160
 * SHA-256 512    32    256
 * SHA-384 1024   64    384
 * SHA-512 1024   64    512
 * </pre>
 */
public class SHA512Digest extends LongDigest {

	private static final int DIGEST_LENGTH = 64;

	/**
	 * 기본 생성자
	 */
	public SHA512Digest() {
	}

	/**
	 * 복사 생성자
	 * 
	 * @param t 복사 대상
	 */
	public SHA512Digest(SHA512Digest t) {
		super(t);
	}

	public String getAlgorithmName() {
		return "SHA-512";
	}

	public int getDigestSize() {
		return DIGEST_LENGTH;
	}

	public int doFinal(byte[] out, int outOff) {
		finish();

		Pack.longToBigEndian(H0, out, outOff);
		Pack.longToBigEndian(H1, out, outOff + 8);
		Pack.longToBigEndian(H2, out, outOff + 16);
		Pack.longToBigEndian(H3, out, outOff + 24);
		Pack.longToBigEndian(H4, out, outOff + 32);
		Pack.longToBigEndian(H5, out, outOff + 40);
		Pack.longToBigEndian(H6, out, outOff + 48);
		Pack.longToBigEndian(H7, out, outOff + 56);

		reset();

		return DIGEST_LENGTH;
	}

	public void reset() {
		super.reset();

		/*
		 * SHA-512의 초기값
		 */
		H0 = 0x6a09e667f3bcc908L;
		H1 = 0xbb67ae8584caa73bL;
		H2 = 0x3c6ef372fe94f82bL;
		H3 = 0xa54ff53a5f1d36f1L;
		H4 = 0x510e527fade682d1L;
		H5 = 0x9b05688c2b3e6c1fL;
		H6 = 0x1f83d9abfb41bd6bL;
		H7 = 0x5be0cd19137e2179L;
	}
}
