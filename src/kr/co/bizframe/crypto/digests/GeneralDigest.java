/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.digests;

import kr.co.bizframe.crypto.ExtendedDigest;

/**
 * "Handbook of Applied Cryptography" pages 344 - 347 를 토대로 한 MD4의 기본 구현이다.
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
	 * J2ME에서 지원하지 않는 Object.clone() 인터페이스 대신 이 생성자를 사용한다.
	 * @param GeneralDigest 
	 */
	protected GeneralDigest(GeneralDigest t) {
		xBuf = new byte[t.xBuf.length];
		System.arraycopy(t.xBuf, 0, xBuf, 0, t.xBuf.length);

		xBufOff = t.xBufOff;
		byteCount = t.byteCount;
	}

	/**
	 * 암복호화 대상을  byte 형태로 Digest를 갱신한다.
	 * @param in 암복호화 대상인 byte 데이터
	 */
	public void update(byte in) {
		xBuf[xBufOff++] = in;

		if (xBufOff == xBuf.length) {
			processWord(xBuf, 0);
			xBufOff = 0;
		}

		byteCount++;
	}

	/**
	 * 
	 * 암복호화 대상을  byte 형태로 지정된 inOff로부터 시작하여 Digest를 갱신한다.
	 * @param in 암복호화 대상인 byte 데이터
	 * @param inOff 시작 offset
	 * @param len 사용되는 바이트 수 
	 */
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
	 * 패딩 등의 최종 처리를 하여 Digest를 완료한다.
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

	/**
	 * 초기화 시킨다.
	 */
	public void reset() {
		byteCount = 0;

		xBufOff = 0;
		for (int i = 0; i < xBuf.length; i++) {
			xBuf[i] = 0;
		}
	}

	/**
	 * byte 길이를 반환한다.
	 * @return byte 길이 64
	 */
	public int getByteLength() {
		return BYTE_LENGTH;
	}

	protected abstract void processWord(byte[] in, int inOff);

	protected abstract void processLength(long bitLength);

	protected abstract void processBlock();
}
