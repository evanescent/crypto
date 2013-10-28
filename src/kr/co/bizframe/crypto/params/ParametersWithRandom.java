/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import java.security.SecureRandom;

import kr.co.bizframe.crypto.CipherParameters;

public class ParametersWithRandom implements CipherParameters {
	private SecureRandom random;
	private CipherParameters parameters;

	public ParametersWithRandom(CipherParameters parameters, SecureRandom random) {
		this.random = random;
		this.parameters = parameters;
	}

	public ParametersWithRandom(CipherParameters parameters) {
		this(parameters, new SecureRandom());
	}

	public SecureRandom getRandom() {
		return random;
	}

	public CipherParameters getParameters() {
		return parameters;
	}
}
