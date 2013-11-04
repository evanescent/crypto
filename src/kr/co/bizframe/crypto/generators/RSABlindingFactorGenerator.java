/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import kr.co.bizframe.crypto.CipherParameters;
import kr.co.bizframe.crypto.params.ParametersWithRandom;
import kr.co.bizframe.crypto.params.RSAKeyParameters;
import kr.co.bizframe.crypto.params.RSAPrivateCrtKeyParameters;

/**
 * Generate a random factor suitable for use with RSA blind signatures as
 * outlined in Chaum's blinding and unblinding as outlined in
 * "Handbook of Applied Cryptography", page 475.
 */
public class RSABlindingFactorGenerator {

	private static BigInteger ZERO = BigInteger.valueOf(0);
	private static BigInteger ONE = BigInteger.valueOf(1);

	private RSAKeyParameters key;
	private SecureRandom random;

	/**
	 * Initialise the factor generator
	 *
	 * @param param
	 *            the necessary RSA key parameters.
	 */
	public void init(CipherParameters param) {
		if (param instanceof ParametersWithRandom) {
			ParametersWithRandom rParam = (ParametersWithRandom) param;

			key = (RSAKeyParameters) rParam.getParameters();
			random = rParam.getRandom();
		} else {
			key = (RSAKeyParameters) param;
			random = new SecureRandom();
		}

		if (key instanceof RSAPrivateCrtKeyParameters) {
			throw new IllegalArgumentException(
					"generator requires RSA public key");
		}
	}

	/**
	 * Generate a suitable blind factor for the public key the generator was
	 * initialised with.
	 *
	 * @return a random blind factor
	 */
	public BigInteger generateBlindingFactor() {
		if (key == null) {
			throw new IllegalStateException("generator not initialised");
		}

		BigInteger m = key.getModulus();
		int length = m.bitLength() - 1; // must be less than m.bitLength()
		BigInteger factor;
		BigInteger gcd;

		do {
			factor = new BigInteger(length, random);
			gcd = factor.gcd(m);
		} while (factor.equals(ZERO) || factor.equals(ONE) || !gcd.equals(ONE));

		return factor;
	}
}
