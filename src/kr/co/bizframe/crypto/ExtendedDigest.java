/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * �ؽ� �Լ��� Ȯ�� �������̽�
 */
public interface ExtendedDigest extends Digest {

	/**
	 * �ؽ� �Լ��� ���� ��� ���� ũ�⸦ ��ȯ�Ѵ�.
	 *
	 * @return �ؽ� �Լ��� ���� ��� ���� ũ��
	 */
	public int getByteLength();
	
}
