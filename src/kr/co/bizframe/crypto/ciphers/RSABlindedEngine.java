/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.ciphers;

import java.math.BigInteger;
import java.security.SecureRandom;

import kr.co.bizframe.crypto.AsymmetricBlockCipher;
import kr.co.bizframe.crypto.CipherParameters;
import kr.co.bizframe.crypto.params.ParametersWithRandom;
import kr.co.bizframe.crypto.params.RSAKeyParameters;
import kr.co.bizframe.crypto.params.RSAPrivateCrtKeyParameters;
import kr.co.bizframe.crypto.util.BigIntegers;

/**
 * 블라인딩이 포함된 RSA 기본 구현 엔진
 */
public class RSABlindedEngine implements AsymmetricBlockCipher {
	
	private static BigInteger ONE = BigInteger.valueOf(1);

	private RSACoreEngine core = new RSACoreEngine();
	private RSAKeyParameters key;
	private SecureRandom random;

	public void init(boolean forEncryption, CipherParameters param) {
		core.init(forEncryption, param);

		if (param instanceof ParametersWithRandom) {
			ParametersWithRandom rParam = (ParametersWithRandom) param;

			key = (RSAKeyParameters) rParam.getParameters();
			random = rParam.getRandom();
		} else {
			key = (RSAKeyParameters) param;
			random = new SecureRandom();
		}
	}

	/**
	 * 입력 블록의 최대 크기를 반환한다.
	 * 암호화 시에는 항상 키 길이보다 1 바이트가 작고,
	 * 복호화 시에는 키 길이와 같다.
	 *
	 * @return 입력 블록의 최대 크기
	 */
	public int getInputBlockSize() {
		return core.getInputBlockSize();
	}

	/**
	 * 출력 블록의 최대 크기를 반환한다.
	 * 복호화 시에는 항상 키 길이보다 1 바이트가 작고,
	 * 암호화 시에는 키 길이와 같다.
	 *
	 * @return 출력 블록의 최대 크기
	 */
	public int getOutputBlockSize() {
		return core.getOutputBlockSize();
	}

	public byte[] processBlock(byte[] in, int inOff, int inLen) {
		if (key == null) {
			throw new IllegalStateException("RSA engine not initialised");
		}

		BigInteger input = core.convertInput(in, inOff, inLen);

		BigInteger result;
		if (key instanceof RSAPrivateCrtKeyParameters) {
			RSAPrivateCrtKeyParameters k = (RSAPrivateCrtKeyParameters) key;

			BigInteger e = k.getPublicExponent();
			if (e != null) // can't do blinding without a public exponent
			{
				BigInteger m = k.getModulus();
				BigInteger r = BigIntegers.createRandomInRange(ONE, m
						.subtract(ONE), random);

				BigInteger blindedInput = r.modPow(e, m).multiply(input).mod(m);
				BigInteger blindedResult = core.processBlock(blindedInput);

				BigInteger rInv = r.modInverse(m);
				result = blindedResult.multiply(rInv).mod(m);
			} else {
				result = core.processBlock(input);
			}
		} else {
			result = core.processBlock(input);
		}

		return core.convertOutput(result);
	}
}
