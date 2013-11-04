/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import kr.co.bizframe.crypto.AsymmetricCipherKeyPair;
import kr.co.bizframe.crypto.AsymmetricCipherKeyPairGenerator;
import kr.co.bizframe.crypto.KeyGenerationParameters;
import kr.co.bizframe.crypto.params.KCDSAKeyGenerationParameters;
import kr.co.bizframe.crypto.params.KCDSAParameters;
import kr.co.bizframe.crypto.params.KCDSAPrivateKeyParameters;
import kr.co.bizframe.crypto.params.KCDSAPublicKeyParameters;
import kr.co.bizframe.crypto.prngs.KCDSARandomGenerator;
import kr.co.bizframe.crypto.util.ByteUtil;

import org.apache.log4j.Logger;

public class KCDSAKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {

	private KCDSAKeyGenerationParameters param;

	private boolean _test = Boolean.getBoolean("bfsec.test.vector");
	private boolean _debug = Boolean.getBoolean("bfsec.debug");
	private Logger _logger = Logger.getLogger(KCDSAKeyPairGenerator.class);

	public void init(KeyGenerationParameters param) {
		this.param = (KCDSAKeyGenerationParameters) param;
	}

	public AsymmetricCipherKeyPair generateKeyPair() {
		BigInteger p, q, g, x, y;
		KCDSAParameters kcdsaParams = param.getParameters();
		SecureRandom random = param.getRandom();

		q = kcdsaParams.getQ();
		p = kcdsaParams.getP();
		g = kcdsaParams.getG();

		do {
			int qBitLength = q.bitLength();
			KCDSARandomGenerator prng = new KCDSARandomGenerator();

			byte[] randomInput = new byte[qBitLength / 8];
			random.nextBytes(randomInput);
			BigInteger xKey = new BigInteger(randomInput);
			if (_test) {
				xKey = new BigInteger(new byte[] { (byte) 0xf2, (byte) 0x07,
						(byte) 0x2c, (byte) 0xe3, (byte) 0x0a, (byte) 0x01,
						(byte) 0x76, (byte) 0x56, (byte) 0x83, (byte) 0x24,
						(byte) 0x56, (byte) 0x4b, (byte) 0xfd, (byte) 0xbd,
						(byte) 0x70, (byte) 0x77, (byte) 0x17, (byte) 0x3b,
						(byte) 0x7e, (byte) 0x3f });
			}
			random.nextBytes(randomInput);
			if (_test) {
				randomInput = new String(
						"saldjfawp399u374r098u98^%^%hkrgn;lwkrp47t93c%$89439859k"
								+ "jdmnvcm cvk o4u09r 4j oj2out209xfqw;l*&!^#@U#*#$)(# z x"
								+ "o957tc-95 5 v5oiuv9876 6 vj o5iuv-053,mcvlrkfworet")
						.getBytes();
			}
			BigInteger xSeed = prng.nextValue(randomInput, qBitLength);

			BigInteger xVal = xKey.add(xSeed).mod(q);

			x = prng.nextValue(ByteUtil.toByteArray(xVal), qBitLength).mod(q);
			if (_debug) {
				_logger.debug("xSeed: " + ByteUtil.toHexString(xSeed));
				_logger.debug("xKey: " + ByteUtil.toHexString(xKey));
				_logger.debug("xVal: " + ByteUtil.toHexString(xVal));
				_logger.debug("X: " + ByteUtil.toHexString(x));
			}
		} while (x.equals(BigInteger.ZERO) || x.compareTo(q) >= 0);

		y = g.modPow(x.modInverse(q), p);
		if (_debug) {
			_logger.debug("Y: " + ByteUtil.toHexString(y));
		}
		return new AsymmetricCipherKeyPair(new KCDSAPublicKeyParameters(y,
				kcdsaParams), new KCDSAPrivateKeyParameters(x, kcdsaParams));
	}

}
