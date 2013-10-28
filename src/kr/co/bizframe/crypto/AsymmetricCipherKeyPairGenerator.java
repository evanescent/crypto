/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * ����/����� Ű �� �������� �������̽�
 */
public interface AsymmetricCipherKeyPairGenerator {

	/**
	 * �־��� Ű �������� �Ű������� �ʱ�ȭ�Ѵ�.
	 *  
	 * @param param Ű �������� �ʱ�ȭ �Ű�����
	 */
	public void init(KeyGenerationParameters param);

	/**
	 * ����/����� Ű ���� ����, ��ȯ�Ѵ�.
	 *  
	 * @return ������ ����/����� Ű �� 
	 */
	public AsymmetricCipherKeyPair generateKeyPair();
	
}
