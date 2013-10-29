/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import kr.co.bizframe.crypto.CipherParameters;

/**
 * 초기화 벡터를 포함한 암호화 매개변수 클래스
 */
public class ParametersWithIV implements CipherParameters {

	private byte[] iv;
	private CipherParameters parameters;

	/**
	 * 기본 생성자
	 * 
	 * @param parameters 암복호화 시 필요한 매개변수
	 * @param iv 초기화 벡터
	 */
	public ParametersWithIV(CipherParameters parameters, byte[] iv) {
		this(parameters, iv, 0, iv.length);
	}

	/**
	 * 복사 생성자
	 * 
	 * @param parameters 암복호화 시 필요한 매개변수
	 * @param iv 초기화 벡터
	 * @param ivOff 입력 바이트 배열의 시작 위치
	 * @param ivLen 추출할 길이
	 */
	public ParametersWithIV(CipherParameters parameters, byte[] iv, int ivOff,
			int ivLen) {
		this.iv = new byte[ivLen];
		this.parameters = parameters;

		System.arraycopy(iv, ivOff, this.iv, 0, ivLen);
	}

	/**
	 * 초기화 벡터를 반환한다.
	 * 
	 * @return 초기화 벡터
	 */
	public byte[] getIV() {
		return iv;
	}

	/**
	 * 암복호화 시 필요한 매개변수을 반환한다.
	 * 
	 * @return 암복호화 시 필요한 매개변수
	 */
	public CipherParameters getParameters() {
		return parameters;
	}
}
