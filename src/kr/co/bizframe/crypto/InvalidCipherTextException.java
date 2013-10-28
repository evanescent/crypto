/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * ��ȣȭ ������ �ùٸ��� ���� ��� �߻��ϴ� ����
 */
public class InvalidCipherTextException extends CryptoException {

	/**
	 * �⺻ ������
	 */
	public InvalidCipherTextException() {
	}

	/**
	 * �־��� �޽����� ������ ������
	 *
	 * @param message ������ ��� ���� �޽���
	 */
	public InvalidCipherTextException(String message) {
		super(message);
	}
}
