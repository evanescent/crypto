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

<<<<<<< HEAD
	/**
	 * 기본 생성자
	 * 
	 * @param privateKey 개인키 설정 여부
	 */
=======
>>>>>>> parent of 8173965... 주석 (10)
	public AsymmetricKeyParameter(boolean privateKey) {
		this.privateKey = privateKey;
	}

<<<<<<< HEAD
	/**
	 * 개인키 설정 여부를 반환한다.
	 * 
	 * @return <code>true</code>면 개인키, <code>false</code>면 공개키
	 */
=======
>>>>>>> parent of 8173965... 주석 (10)
	public boolean isPrivate() {
		return privateKey;
	}
}
