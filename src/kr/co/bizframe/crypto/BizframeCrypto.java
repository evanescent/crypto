/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

import kr.co.bizframe.crypto.ciphers.ARIAEngine;
import kr.co.bizframe.crypto.ciphers.CipherManager;
import kr.co.bizframe.crypto.ciphers.SEEDEngine;
import kr.co.bizframe.crypto.digests.DigestManager;
import kr.co.bizframe.crypto.digests.SHA1Digest;
import kr.co.bizframe.crypto.modes.CBCBlockCipher;

public class BizframeCrypto {

	private Algorithms algos  = new Algorithms();

	public BizframeCrypto(){
		init();
	}

	public void init() {
		// 검증 대상 함수로딩
		loadApproved();

		// 비검증 대상 함수 로딩
		loadUnapproved();
	}

	private void loadApproved() {
		algos.addBlockCipher("SEED", SEEDEngine.class);
		algos.addBlockCipher("ARIA", ARIAEngine.class);

		algos.addBlockCipher("SEED_ECB", SEEDEngine.class);
		algos.addBlockCipher("ARIA_ECB", ARIAEngine.class);

		algos.addBlockCipher("SEED_CBC", SEEDEngine.class, CBCBlockCipher.class);
		algos.addBlockCipher("ARIA_CBC", ARIAEngine.class, CBCBlockCipher.class);

		algos.addDigest("SHA1", SHA1Digest.class);
		algos.addDigest("SHA256", SHA1Digest.class);
	}

	private void loadUnapproved() {

	}

	public CipherManager getBlockCipher(String name) {
		return algos.getBlockCipher(name);
	}

	public DigestManager getDigest(String name) {
		return algos.getDigest(name);
	}
	
}
