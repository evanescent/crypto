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
 * 
 */
public class ParametersWithRandom implements CipherParameters {
	private SecureRandom random;
	private CipherParameters parameters;

	/**
	 * 
	 * @param parameters
	 * @param random
	 */
	public ParametersWithRandom(CipherParameters parameters, SecureRandom random) {
		this.random = random;
		this.parameters = parameters;
	}

	/**
	 * 
	 * @param parameters
	 */
	public ParametersWithRandom(CipherParameters parameters) {
		this(parameters, new SecureRandom());
	}

	/**
	 * 
	 * @return
	 */
	public SecureRandom getRandom() {
		return random;
	}

	/**
	 * 
	 * @return
	 */
	public CipherParameters getParameters() {
		return parameters;
	}
}
