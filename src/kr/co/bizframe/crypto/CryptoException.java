/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * crypto 모듈에 의해 발생하는 기본 오류 클래스
 */
public class CryptoException extends Exception {

	/**
	 * 기본 생성자.
	 */
	public CryptoException() {
	}

	/**
	 * 주어진 메시지를 가지는 생성자
	 *
	 * @param message 오류가 담고 있을 메시지
	 */
	public CryptoException(String message) {
		super(message);
	}

}
