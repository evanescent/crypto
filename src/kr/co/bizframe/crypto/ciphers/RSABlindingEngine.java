/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.ciphers;

import java.math.BigInteger;

import kr.co.bizframe.crypto.AsymmetricBlockCipher;
import kr.co.bizframe.crypto.CipherParameters;
import kr.co.bizframe.crypto.params.ParametersWithRandom;
import kr.co.bizframe.crypto.params.RSABlindingParameters;
import kr.co.bizframe.crypto.params.RSAKeyParameters;

/**
 * Blind RSA 서명 엔진
 */
public class RSABlindingEngine implements AsymmetricBlockCipher {

	private RSACoreEngine core = new RSACoreEngine();

	private RSAKeyParameters key;
	private BigInteger blindingFactor;

	private boolean forEncryption;

	public void init(boolean forEncryption, CipherParameters param) {
		RSABlindingParameters p;

		if (param instanceof ParametersWithRandom) {
			ParametersWithRandom rParam = (ParametersWithRandom) param;

			p = (RSABlindingParameters) rParam.getParameters();
		} else {
			p = (RSABlindingParameters) param;
		}

		core.init(forEncryption, p.getPublicKey());

		this.forEncryption = forEncryption;
		this.key = p.getPublicKey();
		this.blindingFactor = p.getBlindingFactor();
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
		BigInteger msg = core.convertInput(in, inOff, inLen);

		if (forEncryption) {
			msg = blindMessage(msg);
		} else {
			msg = unblindMessage(msg);
		}

		return core.convertOutput(msg);
	}

	/*
	 * Blind message with the blind factor.
	 */
	private BigInteger blindMessage(BigInteger msg) {
		BigInteger blindMsg = blindingFactor;
		blindMsg = msg.multiply(blindMsg.modPow(key.getExponent(), key
				.getModulus()));
		blindMsg = blindMsg.mod(key.getModulus());

		return blindMsg;
	}

	/*
	 * Unblind the message blinded with the blind factor.
	 */
	private BigInteger unblindMessage(BigInteger blindedMsg) {
		BigInteger m = key.getModulus();
		BigInteger msg = blindedMsg;
		BigInteger blindFactorInverse = blindingFactor.modInverse(m);
		msg = msg.multiply(blindFactorInverse);
		msg = msg.mod(m);

		return msg;
	}
}
