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
public class ParametersWithIV implements CipherParameters {

	private byte[] iv;
	private CipherParameters parameters;

	/**
	 * 기본 생성자
	 * 
	 * @param parameters
	 *            복호화 시 필요한 암호화 시 사용된 파라미터 값
	 * @param iv
	 *            초기 벡터값
	 */
	public ParametersWithIV(CipherParameters parameters, byte[] iv) {
		this(parameters, iv, 0, iv.length);
	}

	/**
	 * 복제 생성자
	 * 
	 * @param parameters
	 *            복호화 시 필요한 암호화 시 사용된 파라미터 값
	 * @param iv
	 *            초기 벡터 값
	 * @param ivOff 입력 바이트 배열
	 * @param ivLen 결과 바이트 배열
	 */
	public ParametersWithIV(CipherParameters parameters, byte[] iv, int ivOff,
			int ivLen) {
		this.iv = new byte[ivLen];
		this.parameters = parameters;

		System.arraycopy(iv, ivOff, this.iv, 0, ivLen);
	}

	/**
	 * 초기화 벡터 값은 반환한다.
	 * 
	 * @return 초기화 벡터
	 */
	public byte[] getIV() {
		return iv;
	}

	/**
	 * 암호화 시 사용된 파라미터 값을 반환한다.
	 * 
	 * @return 암호화시 사용된 파라미터
	 */
	public CipherParameters getParameters() {
		return parameters;
	}
}
