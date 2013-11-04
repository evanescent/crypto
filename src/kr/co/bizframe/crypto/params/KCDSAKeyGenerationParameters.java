package kr.co.bizframe.crypto.params;

import java.security.SecureRandom;

import kr.co.bizframe.crypto.KeyGenerationParameters;

public class KCDSAKeyGenerationParameters
	extends KeyGenerationParameters {

	private KCDSAParameters params;

	public KCDSAKeyGenerationParameters(
			SecureRandom random,
			KCDSAParameters params) {
		super(random, params.getP().bitLength() - 1);

		this.params = params;
	}

	public KCDSAParameters getParameters() {
		return params;
	}
}
