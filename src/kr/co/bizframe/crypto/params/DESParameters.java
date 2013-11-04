/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

/**
 * DES 키 매개변수
 */
public class DESParameters extends KeyParameter {

	/**
	 * DES 키를 바이트 배열로 포함하는 생성자. 
	 * 
	 * @param key 바이트 배열 DES 키
	 * @throws IllegalArgumentException 해당 DES 키가 Weak Key인 경우
	 */
	public DESParameters(byte[] key) {
		super(key);

		if (isWeakKey(key, 0)) {
			throw new IllegalArgumentException("attempt to create weak DES key");
		}
	}

	/*
	 * DES Key length in bytes.
	 */
	static public final int DES_KEY_LENGTH = 8;

	/*
	 * Table of weak and semi-weak keys taken from Schneier pp281
	 */
	static private final int N_DES_WEAK_KEYS = 16;

	static private byte[] DES_weak_keys = {
	/* weak keys */
	(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
			(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x1f, (byte) 0x1f,
			(byte) 0x1f, (byte) 0x1f, (byte) 0x0e, (byte) 0x0e, (byte) 0x0e,
			(byte) 0x0e, (byte) 0xe0, (byte) 0xe0, (byte) 0xe0, (byte) 0xe0,
			(byte) 0xf1, (byte) 0xf1, (byte) 0xf1, (byte) 0xf1, (byte) 0xfe,
			(byte) 0xfe, (byte) 0xfe, (byte) 0xfe, (byte) 0xfe, (byte) 0xfe,
			(byte) 0xfe, (byte) 0xfe,

			/* semi-weak keys */
			(byte) 0x01, (byte) 0xfe, (byte) 0x01, (byte) 0xfe, (byte) 0x01,
			(byte) 0xfe, (byte) 0x01, (byte) 0xfe, (byte) 0x1f, (byte) 0xe0,
			(byte) 0x1f, (byte) 0xe0, (byte) 0x0e, (byte) 0xf1, (byte) 0x0e,
			(byte) 0xf1, (byte) 0x01, (byte) 0xe0, (byte) 0x01, (byte) 0xe0,
			(byte) 0x01, (byte) 0xf1, (byte) 0x01, (byte) 0xf1, (byte) 0x1f,
			(byte) 0xfe, (byte) 0x1f, (byte) 0xfe, (byte) 0x0e, (byte) 0xfe,
			(byte) 0x0e, (byte) 0xfe, (byte) 0x01, (byte) 0x1f, (byte) 0x01,
			(byte) 0x1f, (byte) 0x01, (byte) 0x0e, (byte) 0x01, (byte) 0x0e,
			(byte) 0xe0, (byte) 0xfe, (byte) 0xe0, (byte) 0xfe, (byte) 0xf1,
			(byte) 0xfe, (byte) 0xf1, (byte) 0xfe, (byte) 0xfe, (byte) 0x01,
			(byte) 0xfe, (byte) 0x01, (byte) 0xfe, (byte) 0x01, (byte) 0xfe,
			(byte) 0x01, (byte) 0xe0, (byte) 0x1f, (byte) 0xe0, (byte) 0x1f,
			(byte) 0xf1, (byte) 0x0e, (byte) 0xf1, (byte) 0x0e, (byte) 0xe0,
			(byte) 0x01, (byte) 0xe0, (byte) 0x01, (byte) 0xf1, (byte) 0x01,
			(byte) 0xf1, (byte) 0x01, (byte) 0xfe, (byte) 0x1f, (byte) 0xfe,
			(byte) 0x1f, (byte) 0xfe, (byte) 0x0e, (byte) 0xfe, (byte) 0x0e,
			(byte) 0x1f, (byte) 0x01, (byte) 0x1f, (byte) 0x01, (byte) 0x0e,
			(byte) 0x01, (byte) 0x0e, (byte) 0x01, (byte) 0xfe, (byte) 0xe0,
			(byte) 0xfe, (byte) 0xe0, (byte) 0xfe, (byte) 0xf1, (byte) 0xfe,
			(byte) 0xf1 };

	/**
	 * DES has 16 weak keys. This method will check if the given DES key
	 * material is weak or semi-weak. Key material that is too short is regarded
	 * as weak.
	 * <p>
	 * See <a href="http://www.counterpane.com/applied.html">"Applied
	 * Cryptography"</a> by Bruce Schneier for more information.
	 *
	 * @return true if the given DES key material is weak or semi-weak, false
	 *         otherwise.
	 */
	public static boolean isWeakKey(byte[] key, int offset) {
		if (key.length - offset < DES_KEY_LENGTH) {
			throw new IllegalArgumentException("key material too short.");
		}

		nextkey: for (int i = 0; i < N_DES_WEAK_KEYS; i++) {
			for (int j = 0; j < DES_KEY_LENGTH; j++) {
				if (key[j + offset] != DES_weak_keys[i * DES_KEY_LENGTH + j]) {
					continue nextkey;
				}
			}

			return true;
		}
		return false;
	}

	/**
	 * 홀수 패리티 비트를 설정한다. 후에 키의 올바른지 여부를 체크할 때 사용한다.
	 *
	 * @param bytes 패리티 비트를 설정한 바이트 배열
	 */
	public static void setOddParity(byte[] bytes) {
		for (int i = 0; i < bytes.length; i++) {
			int b = bytes[i];
			bytes[i] = (byte) ((b & 0xfe) | ((((b >> 1) ^ (b >> 2) ^ (b >> 3)
					^ (b >> 4) ^ (b >> 5) ^ (b >> 6) ^ (b >> 7)) ^ 0x01) & 0x01));
		}
	}
}
