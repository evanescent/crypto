/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * 암호화 문구가 올바르지 않은 경우 발생하는 오류
 */
public class InvalidCipherTextException extends CryptoException {

	/**
	 * 기본 생성자
	 */
	public InvalidCipherTextException() {
	}

	/**
	 * 주어진 메시지를 가지는 생성자
	 *
	 * @param message 오류가 담고 있을 메시지
	 */
	public InvalidCipherTextException(String message) {
		super(message);
	}
}
