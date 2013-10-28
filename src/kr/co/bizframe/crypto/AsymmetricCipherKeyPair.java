/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * ����/����� ���� �Ű����� Ŭ����
 */
public class AsymmetricCipherKeyPair {

	private CipherParameters publicParam;
	private CipherParameters privateParam;

	/**
	 * �־��� �Ű������� ����ϴ� ������
	 * 
	 * @param publicParam ����Ű �Ű�����
	 * @param privateParam �����Ű �Ű�����
	 */
	public AsymmetricCipherKeyPair(CipherParameters publicParam,
			CipherParameters privateParam) {
		this.publicParam = publicParam;
		this.privateParam = privateParam;
	}

	/**
	 * ����Ű �Ű������� ��ȯ�Ѵ�.
	 * 
	 * @return ����Ű �Ű�����
	 */
	public CipherParameters getPublic() {
		return publicParam;
	}

	/**
	 * �����Ű �Ű������� ��ȯ�Ѵ�.
	 * 
	 * @return �����Ű �Ű�����
	 */
	public CipherParameters getPrivate() {
		return privateParam;
	}
}
