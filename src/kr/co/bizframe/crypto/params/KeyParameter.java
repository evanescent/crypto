/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import kr.co.bizframe.crypto.CipherParameters;

/**
 * 
 */
public class KeyParameter implements CipherParameters {

	private byte[] key;

	/**
	 * 기본 생성자
	 * 
	 * @param key 입력 바이트 배열 키 값
	 */
	public KeyParameter(byte[] key) {
		this(key, 0, key.length);
	}

	/**
	 * 복사 생성자
	 * 
	 * @param key 입력 바이트 배열 키 값
	 * @param keyOff 입력 바이트 배열의 시작 위치
	 * @param keyLen 추출할 길이
	 */
	public KeyParameter(byte[] key, int keyOff, int keyLen) {
		this.key = new byte[keyLen];

		System.arraycopy(key, keyOff, this.key, 0, keyLen);
	}

	/**
	 * 입력 바이트 배열 키 값을 반환한다.
	 * 
	 * @return 입력 바이트 배열 키 값
	 */
	public byte[] getKey() {
		return key;
	}
}
