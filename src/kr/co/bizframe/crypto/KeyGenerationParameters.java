/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

import java.security.SecureRandom;

/**
 * Ű �����⿡ ������ �Ű������� �⺻ Ŭ����
 */
public class KeyGenerationParameters {

	private SecureRandom random;
	private int strength;

	/**
	 * ����������� ����(��Ʈ)�� �����Ѵ�.
	 * 
	 * @param random ����������
	 * @param strength ������ Ű�� ���� ����(��Ʈ)
	 */
	public KeyGenerationParameters(SecureRandom random, int strength) {
		this.random = random;
		this.strength = strength;
	}

	/**
	 * �����⿡�� ����� ���������⸦ ��ȯ�Ѵ�.
	 * 
	 * @return �����⿡�� ����� ����������
	 */
	public SecureRandom getRandom() {
		return random;
	}

	/**
	 * �����⿡ ���� ���۵� Ű�� ����(��Ʈ)�� ��ȯ�Ѵ�.
	 * 
	 * @return �����⿡ ���� ���۵� Ű�� ����(��Ʈ)
	 */
	public int getStrength() {
		return strength;
	}
}
