/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import kr.co.bizframe.crypto.CipherParameters;

/**
 * 
 */
public class AsymmetricKeyParameter implements CipherParameters {

	boolean privateKey;

	/**
	 * 기본 생성자
	 * 
	 * @param privateKey 개인키 설정
	 */
	public AsymmetricKeyParameter(boolean privateKey) {
		this.privateKey = privateKey;
	}

	/**
	 * 개인키 여부를 체크한다.
	 * 
	 * @return 설정된 키가 개인키인 경우 true, 아닌 경우 false
	 */
	public boolean isPrivate() {
		return privateKey;
	}
}
