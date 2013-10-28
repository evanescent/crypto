/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import kr.co.bizframe.crypto.CipherParameters;

public class AsymmetricKeyParameter implements CipherParameters {
	
	boolean privateKey;

	public AsymmetricKeyParameter(boolean privateKey) {
		this.privateKey = privateKey;
	}

	public boolean isPrivate() {
		return privateKey;
	}
}
