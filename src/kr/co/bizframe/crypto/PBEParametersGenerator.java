/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

import kr.co.bizframe.crypto.util.Strings;

/**
 * 모든 PBE(Password Based Encryption) 매개변수 생성기에서 사용할 부모 클래스
 */
public abstract class PBEParametersGenerator {
	protected byte[] password;
	protected byte[] salt;
	protected int iterationCount;

	/**
	 * 기본 생성자
	 */
	protected PBEParametersGenerator() {
	}

	/**
	 * PBE 생성기를 초기화한다.
	 * 
	 * @param password 비밀번호
	 * @param salt salt
	 * @param iterationCount 반복수
	 */
	public void init(byte[] password, byte[] salt, int iterationCount) {
		this.password = password;
		this.salt = salt;
		this.iterationCount = iterationCount;
	}

	/**
	 * 설정한 비밀번호를 반환한다.
	 *
	 * @return 설정한 비밀번호
	 */
	public byte[] getPassword() {
		return password;
	}

	/**
	 * 설정한 salt를 반환한다.
	 *
	 * @return 설정한 salt
	 */
	public byte[] getSalt() {
		return salt;
	}

	/**
	 * 설정한 반복수를 반환한다.
	 *
	 * @return 설정한 반복수
	 */
	public int getIterationCount() {
		return iterationCount;
	}

	/**
	 * 주어진 키 길이에 따라 유도된 매개변수를 생성한다.
	 *
	 * @param keySize 키 길이 (비트)
	 * @return 생성된 매개변수
	 */
	public abstract CipherParameters generateDerivedParameters(int keySize);

	/**
	 * 주어진 키/IV 길이에 따라 유도된 매개변수를 생성한다.
	 *
	 * @param keySize 키 길이 (비트)
	 * @param ivSize IV 길이 (비트)
	 * @return 생성된 매개변수
	 */
	public abstract CipherParameters generateDerivedParameters(int keySize,
			int ivSize);

	/**
	 * 주어진 키/IV 길이에 따라 유도된 MAC 매개변수를 생성한다.
	 *
	 * @param keySize 키 길이 (비트)
	 * @return 생성된 매개변수
	 */
	public abstract CipherParameters generateDerivedMacParameters(int keySize);

	/**
	 * PKCS #5에 따라 ASCII 문자 배열을 바이트 배열로 변환한다.
	 *
	 * @param password ASCII 문자 배열
	 * @return 변환된 바이트 배열
	 */
	public static byte[] PKCS5PasswordToBytes(char[] password) {
		byte[] bytes = new byte[password.length];

		for (int i = 0; i != bytes.length; i++) {
			bytes[i] = (byte) password[i];
		}

		return bytes;
	}

	/**
	 * PKCS #5에 따라 UTF-8 문자 배열을 바이트 배열로 변환한다.
	 *
	 * @param password UTF-8 문자 배열
	 * @return 변환된 바이트 배열
	 */
	public static byte[] PKCS5PasswordToUTF8Bytes(char[] password) {
		return Strings.toUTF8ByteArray(password);
	}

	/**
	 * PKCS #12에 따라 (2개의 패드 바이트가 끝에 추가된) 유니코드(빅 엔디안) 배열을 
	 * 바이트 배열로 변환한다.
	 *
	 * @param password 유니코드(빅 엔디안) 문자 배열
	 * @return 변환된 바이트 배열
	 */
	public static byte[] PKCS12PasswordToBytes(char[] password) {
		if (password.length > 0) {
			// +1 for extra 2 pad bytes.
			byte[] bytes = new byte[(password.length + 1) * 2];

			for (int i = 0; i != password.length; i++) {
				bytes[i * 2] = (byte) (password[i] >>> 8);
				bytes[i * 2 + 1] = (byte) password[i];
			}

			return bytes;
		} else {
			return new byte[0];
		}
	}
}
