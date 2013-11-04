/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import java.security.SecureRandom;

import kr.co.bizframe.crypto.CipherParameters;

/**
 * 난수발생기를 포함하는 매개변수
 * 
 */
public class ParametersWithRandom implements CipherParameters {
	private SecureRandom random;
	private CipherParameters parameters;

	/**
	 * 암/복호화에 필요한 매개변수와 난수발생기를 포함하는 생성자.
	 * 
	 * @param parameters 암/복호화에 필요한 매개변수
	 * @param random 난수발생기
	 */
	public ParametersWithRandom(CipherParameters parameters, SecureRandom random) {
		this.random = random;
		this.parameters = parameters;
	}

	/**
	 * 암/복호화에 필요한 매개변수를 포함하는 생성자.
	 * 
	 * @param parameters 암/복호화에 필요한 매개변수
	 */
	public ParametersWithRandom(CipherParameters parameters) {
		this(parameters, new SecureRandom());
	}

	/**
	 * 난수발생기를 반환한다.
	 * 
	 * @return 난수발생기
	 */
	public SecureRandom getRandom() {
		return random;
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
