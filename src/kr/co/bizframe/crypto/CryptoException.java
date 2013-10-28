/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * crypto 모듈에 의해 발생하는 오류에 대한 기본 Exception 클래스
 *
 */
public class CryptoException extends Exception {

	/**
	 * base constructor.
	 */
	public CryptoException() {
	}

	/**
	 * create a CryptoException with the given message.
	 *
	 * @param message
	 *            the message to be carried with the exception.
	 */
	public CryptoException(String message) {
		super(message);
	}

}
