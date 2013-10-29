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
	 * 
	 * @param key
	 */
	public KeyParameter(byte[] key) {
		this(key, 0, key.length);
	}

	/**
	 * 
	 * @param key
	 * @param keyOff
	 * @param keyLen
	 */
	public KeyParameter(byte[] key, int keyOff, int keyLen) {
		this.key = new byte[keyLen];

		System.arraycopy(key, keyOff, this.key, 0, keyLen);
	}

	/**
	 * 
	 * @return
	 */
	public byte[] getKey() {
		return key;
	}
}
