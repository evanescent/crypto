/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

public class DESParameters extends KeyParameter {

<<<<<<< HEAD
	/**
	 * 기본 생성자
	 * 
	 * @param key 대칭키 바이트 배열
	 */
=======
>>>>>>> parent of 8173965... 주석 (10)
	public DESParameters(byte[] key) {
		super(key);

		if (isWeakKey(key, 0)) {
			throw new IllegalArgumentException("attempt to create weak DES key");
		}
	}

	/*
	 * DES 대칭키 사이즈
	 */
	static public final int DES_KEY_LENGTH = 8;

	/*
	 * Scheneier pp281 DES 취약키 및 준 취약키 테이블.
	 */
	static private final int N_DES_WEAK_KEYS = 16;

	static private byte[] DES_weak_keys = {
	/* weak keys (취약키) */
	(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
			(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x1f, (byte) 0x1f,
			(byte) 0x1f, (byte) 0x1f, (byte) 0x0e, (byte) 0x0e, (byte) 0x0e,
			(byte) 0x0e, (byte) 0xe0, (byte) 0xe0, (byte) 0xe0, (byte) 0xe0,
			(byte) 0xf1, (byte) 0xf1, (byte) 0xf1, (byte) 0xf1, (byte) 0xfe,
			(byte) 0xfe, (byte) 0xfe, (byte) 0xfe, (byte) 0xfe, (byte) 0xfe,
			(byte) 0xfe, (byte) 0xfe,

			/* semi-weak keys (준 취약키) */
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
	 * DES 대칭키가 16개의 취약키 혹은 준 취약키에 속하는지 체크한다. 
	 * 
	 * @return DES 대칭키가 취약키 혹은 준 취약키의 경우 <code>true</code>, 아닌 경우 <code>false</code>
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
	 * 
	 * DES 대칭키는 LSB의 홀수 패리티 비트를 설정한다. 올바른 키의 여부를 체크한다.
	 * 
	 * @param bytes 패리티 비트를 추가하기 위한 바이트 배열
	 */
	public static void setOddParity(byte[] bytes) {
		for (int i = 0; i < bytes.length; i++) {
			int b = bytes[i];
			bytes[i] = (byte) ((b & 0xfe) | ((((b >> 1) ^ (b >> 2) ^ (b >> 3)
					^ (b >> 4) ^ (b >> 5) ^ (b >> 6) ^ (b >> 7)) ^ 0x01) & 0x01));
		}
	}
}
