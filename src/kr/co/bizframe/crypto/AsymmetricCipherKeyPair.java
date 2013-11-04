/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * 공개/비공개 쌍의 매개변수 클래스
 */
public class AsymmetricCipherKeyPair {

	private CipherParameters publicParam;
	private CipherParameters privateParam;

	/**
	 * 주어진 매개변수를 사용하는 생성자
	 * 
	 * @param publicParam 공개키 매개변수
	 * @param privateParam 비공개키 매개변수
	 */
	public AsymmetricCipherKeyPair(CipherParameters publicParam,
			CipherParameters privateParam) {
		this.publicParam = publicParam;
		this.privateParam = privateParam;
	}

	/**
	 * 공개키 매개변수를 반환한다.
	 * 
	 * @return 공개키 매개변수
	 */
	public CipherParameters getPublic() {
		return publicParam;
	}

	/**
	 * 비공개키 매개변수를 반환한다.
	 * 
	 * @return 비공개키 매개변수
	 */
	public CipherParameters getPrivate() {
		return privateParam;
	}
}
