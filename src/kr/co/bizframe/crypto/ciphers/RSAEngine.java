/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.ciphers;

import kr.co.bizframe.crypto.AsymmetricBlockCipher;
import kr.co.bizframe.crypto.CipherParameters;

/**
 * RSA 기본 구현 엔진
 */
public class RSAEngine implements AsymmetricBlockCipher {

	private RSACoreEngine core;

	public void init(boolean forEncryption, CipherParameters param) {
		if (core == null) {
			core = new RSACoreEngine();
		}

		core.init(forEncryption, param);
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
		if (core == null) {
			throw new IllegalStateException("RSA engine not initialised");
		}

		return core.convertOutput(core.processBlock(core.convertInput(in,
				inOff, inLen)));
	}
}
