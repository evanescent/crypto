/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

import java.security.SecureRandom;

/**
 * ��Ī ��ȣȭ Ű �������� �⺻ Ŭ����
 */
public class CipherKeyGenerator {

	protected SecureRandom random;
	protected int strength;

	/**
	 * ������ Ű�� ���� �Ű������� �����Ѵ�. 
	 * 
	 * @param param ������ Ű�� ���� �Ű�����
	 */
	public void init(KeyGenerationParameters param) {
		this.random = param.getRandom();
		this.strength = (param.getStrength() + 7) / 8;
	}

	/**
	 * Ű�� ������ ��ȯ�Ѵ�.
	 * 
	 * @return ������ Ű
	 */
	public byte[] generateKey() {
		byte[] key = new byte[strength];

		random.nextBytes(key);

		return key;
	}

}
