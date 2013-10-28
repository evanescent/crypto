/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * KCDSA�� ���� �������̽�
 */
public interface KCDSA extends DSA {

	/**
	 * ó�� �� �غ� �� ȣ���Ѵ�.
	 */
	public void prepare();

	/**
	 * ����� �ؽ� �Լ��� �����Ѵ�.
	 * 
	 * @param digest ����� �ؽ� �Լ�
	 */
	public void setDigest(ExtendedDigest digest);

}
