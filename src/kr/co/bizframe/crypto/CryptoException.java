/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * crypto ��⿡ ���� �߻��ϴ� �⺻ ���� Ŭ����
 */
public class CryptoException extends Exception {

	/**
	 * �⺻ ������.
	 */
	public CryptoException() {
	}

	/**
	 * �־��� �޽����� ������ ������
	 *
	 * @param message ������ ��� ���� �޽���
	 */
	public CryptoException(String message) {
		super(message);
	}

}
