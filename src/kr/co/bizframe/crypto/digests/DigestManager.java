/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.digests;

import kr.co.bizframe.crypto.Digest;

/**
 * {@link kr.co.bizframe.crypto.Digest}의 래퍼 클래스
 */
public class DigestManager {

	private Digest digest;

	/**
	 * 
	 * 
	 * @param digest Digest 구현 인터페이스
	 */
	public DigestManager(Digest digest) {
		this.digest = digest;
	}

	/**
	 * 해쉬함수의 결과 크기를 반환한다.
	 * 
	 * @return 해쉬함수의 결과 크기
	 */
	public int getDigestSize() {
		return digest.getDigestSize();
	}

	/**
	 * 주어진 바이트로 업데이트한다.
	 * 
	 * @param in 입력 바이트
	 */
	public void update(byte in) {
		digest.update(in);
	}

	/**
	 * 주어진 바이트 배열로 업데이트한다.
	 * 
	 * @param in 입력 바이트 배열
	 * @param inOff 입력 바이트 위치
	 * @param len 입력 바이트 길이
	 */
	public void update(byte[] in, int inOff, int len) {
		digest.update(in, inOff, len);
	}

	/**
	 * 결과를 반환한다.
	 * 
	 * @return byte[] 결과 바이트 배열
	 */
	public byte[] digest() {
		byte[] digestBytes = new byte[digest.getDigestSize()];
		digest.doFinal(digestBytes, 0);
		return digestBytes;
	}

	/**
	 * 상태를 초기화 전으로 돌린다.
	 */
	public void reset() {
		digest.reset();
	}

}
