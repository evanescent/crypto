/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import kr.co.bizframe.crypto.CipherParameters;

/**
 * 대칭키 매개변수
 */
public class KeyParameter implements CipherParameters {

	private byte[] key;

	/**
	 * 대칭키를 바이트 배열로 포함하는 생성자. 
	 * 
	 * @param key 대칭키 바이트 배열
	 */
	public KeyParameter(byte[] key) {
		this(key, 0, key.length);
	}

	/**
	 * 대칭키를 바이트 배열로 포함하는 생성자.
	 * 
	 * @param key 대칭키 바이트 배열
	 * @param keyOff 대칭키 바이트 배열 시작 위치
	 * @param keyLen 대칭키 바이트 배열 길이
	 */
	public KeyParameter(byte[] key, int keyOff, int keyLen) {
		this.key = new byte[keyLen];

		System.arraycopy(key, keyOff, this.key, 0, keyLen);
	}

	/**
	 * 대칭키를 바이트 배열로 반환한다.
	 * 
	 * @return 바이트 배열 대칭키
	 */
	public byte[] getKey() {
		return key;
	}
}
