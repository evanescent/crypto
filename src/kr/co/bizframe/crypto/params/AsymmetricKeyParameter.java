/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import kr.co.bizframe.crypto.CipherParameters;

/**
 * 비대칭키 매개변수
 */
public class AsymmetricKeyParameter implements CipherParameters {
	
	boolean privateKey;

	/**
	 * 비공개키 여부를 포함하는 생성자.
	 * 
	 * @param privateKey 비공개키 여부. 
	 *                   <code>true</code>면 비공개키, <code>false</code>면 공개키 
	 */
	public AsymmetricKeyParameter(boolean privateKey) {
		this.privateKey = privateKey;
	}

	/**
	 * 비공개키 여부를 반환한다.
	 * 
	 * @return 비공개키 여부
	 */
	public boolean isPrivate() {
		return privateKey;
	}
}
