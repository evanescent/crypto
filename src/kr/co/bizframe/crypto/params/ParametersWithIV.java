/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import kr.co.bizframe.crypto.CipherParameters;

/**
 * IV를 포함하는 매개변수
 */
public class ParametersWithIV implements CipherParameters {

	private byte[] iv;
	private CipherParameters parameters;

	/**
	 * 암/복호화에 필요한 매개변수와 IV를 포함하는 생성자.
	 * 
	 * @param parameters 암/복호화에 필요한 매개변수
	 * @param iv IV
	 */
	public ParametersWithIV(CipherParameters parameters, byte[] iv) {
		this(parameters, iv, 0, iv.length);
	}

	/**
	 * 암/복호화에 필요한 매개변수와 IV를 포함하는 생성자.
	 * 
	 * @param parameters 암/복호화에 필요한 매개변수
	 * @param iv IV 바이트 배열
	 * @param ivOff IV 바이트 배열의 시작 위치
	 * @param ivLen IV 바이트 배열의 사용 길이
	 */
	public ParametersWithIV(CipherParameters parameters, byte[] iv, 
			int ivOff, int ivLen) {
		this.iv = new byte[ivLen];
		this.parameters = parameters;

		System.arraycopy(iv, ivOff, this.iv, 0, ivLen);
	}

	/**
	 * IV를 반환한다.
	 * 
	 * @return IV
	 */
	public byte[] getIV() {
		return iv;
	}

	/**
	 * 암/복호화에 필요한 매개변수를 반환한다.
	 * 
	 * @return 암/복호화에 필요한 매개변수
	 */
	public CipherParameters getParameters() {
		return parameters;
	}
}
