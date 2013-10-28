/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * 이 오류는 주어진 입력의 길이가 충분치 않아 출력 결과를 생성할 수 없는 경우 발생한다.
 */
public class DataLengthException extends RuntimeCryptoException {

	/**
	 * 기본 생성자
	 */
	public DataLengthException() {
	}

	/**
	 * 주어진 메시지를 가지는 생성자
	 * 
	 * @param message 오류가 담고 있을 메시지
	 */
	public DataLengthException(String message) {
		super(message);
	}
}
