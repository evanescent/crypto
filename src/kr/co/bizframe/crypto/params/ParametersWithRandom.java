/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import java.security.SecureRandom;

import kr.co.bizframe.crypto.CipherParameters;

<<<<<<< HEAD
/**
 * 난수를 포함한 암호화 매개변수 클래스
 */
=======
>>>>>>> parent of 8173965... 주석 (10)
public class ParametersWithRandom implements CipherParameters {
	private SecureRandom random;
	private CipherParameters parameters;

<<<<<<< HEAD
	/**
	 * 기본 생성자
	 * 
	 * @param parameters 암복호화 시 필요한 매개변수
	 */
	public ParametersWithRandom(CipherParameters parameters) {
		this(parameters, new SecureRandom());
	}

	/**
	 * 복사 생성자
	 * 
	 * @param parameters 암복호화 시 필요한 매개변수
	 * @param random 암복호화 시 필요한 난수
	 */
	public ParametersWithRandom(CipherParameters parameters, SecureRandom random) {
		this.random = random;
		this.parameters = parameters;
	}

	/**
	 * 암복호화 시 필요한 난수를 반환한다.
	 * 
	 * @return 암복호화 시 필요한 난수
	 */
=======
	public ParametersWithRandom(CipherParameters parameters, SecureRandom random) {
		this.random = random;
		this.parameters = parameters;
	}

	public ParametersWithRandom(CipherParameters parameters) {
		this(parameters, new SecureRandom());
	}

>>>>>>> parent of 8173965... 주석 (10)
	public SecureRandom getRandom() {
		return random;
	}

<<<<<<< HEAD
	/**
	 * 암복호화 시 필요한 매개변수를 반환한다.
	 * 
	 * @return 암복호화 시 필요한 매개변수
	 */
=======
>>>>>>> parent of 8173965... 주석 (10)
	public CipherParameters getParameters() {
		return parameters;
	}
}
