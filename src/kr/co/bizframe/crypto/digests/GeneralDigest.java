/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.digests;

import kr.co.bizframe.crypto.ExtendedDigest;

/**
 * MD4의 기본 구현. 기타 MD4 family의 골자가 된다.
 */
public abstract class GeneralDigest implements ExtendedDigest {

	private static final int BYTE_LENGTH = 64;
	private byte[] xBuf;
	private int xBufOff;

	private long byteCount;

	/**
	 * 기본 생성자
	 */
	protected GeneralDigest() {
		xBuf = new byte[4];
		xBufOff = 0;
	}

	/**
	 * 복사 생성자
	 * 
	 * @param t 복사 대상
	 */
	protected GeneralDigest(GeneralDigest t) {
		xBuf = new byte[t.xBuf.length];
		System.arraycopy(t.xBuf, 0, xBuf, 0, t.xBuf.length);

		xBufOff = t.xBufOff;
		byteCount = t.byteCount;
	}

	public void update(byte in) {
		xBuf[xBufOff++] = in;

		if (xBufOff == xBuf.length) {
			processWord(xBuf, 0);
			xBufOff = 0;
		}

		byteCount++;
	}

	public void update(byte[] in, int inOff, int len) {
		//
		// 현재 단어를 채운다.
		//
		while ((xBufOff != 0) && (len > 0)) {
			update(in[inOff]);

			inOff++;
			len--;
		}

		//
		// 모든 단어를 처리한다.
		//
		while (len > xBuf.length) {
			processWord(in, inOff);

			inOff += xBuf.length;
			len -= xBuf.length;
			byteCount += xBuf.length;
		}

		//
		// 남겨진 단어를 로드시킨다.
		//
		while (len > 0) {
			update(in[inOff]);

			inOff++;
			len--;
		}
	}

	/**
	 * 패딩 등의 최종 처리를 완료한다.
	 */
	public void finish() {
		long bitLength = (byteCount << 3);

		//
		// 패딩 바이트를 추가한다.
		//
		update((byte) 128);

		while (xBufOff != 0) {
			update((byte) 0);
		}

		processLength(bitLength);

		processBlock();
	}

	public void reset() {
		byteCount = 0;

		xBufOff = 0;
		for (int i = 0; i < xBuf.length; i++) {
			xBuf[i] = 0;
		}
	}

	public int getByteLength() {
		return BYTE_LENGTH;
	}

	protected abstract void processWord(byte[] in, int inOff);

	protected abstract void processLength(long bitLength);

	protected abstract void processBlock();
}
