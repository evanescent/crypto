/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

import java.math.BigInteger;

/**
 * ���ڼ��� �˰����� �����ؾ� �� �������̽�.
 */
public interface DSA {

	/**
	 * ���ڼ��� ���� �Ǵ� ���� �ÿ� ȣ���� �ʱ�ȭ �Լ�
	 *
	 * @param forSigning ���ڼ��� ���� ����, <code>true</code>�� ����, 
	 *                   <code>false</code>�� ����.
	 * @param params ó���� �ʿ��� Ű�� ��Ÿ �ʱ�ȭ �Ű�����
	 */
	public void init(boolean forSigning, CipherParameters param);

	/**
	 * �־��� ����Ʈ �迭�� ���� ���ڼ����� �����Ѵ�.
	 *
	 * @param message ������ �޽��� ����Ʈ �迭
	 * @return r�� s�� ǥ���Ǵ� 2���� ū ������
	 */
	public BigInteger[] generateSignature(byte[] message);

	/**
	 * verify the message message against the signature values r and s.
	 *
	 * @param message
	 *            the message that was supposed to have been signed.
	 * @param r
	 *            the r signature value.
	 * @param s
	 *            the s signature value.
	 */
	public boolean verifySignature(byte[] message, BigInteger r, BigInteger s);
}
