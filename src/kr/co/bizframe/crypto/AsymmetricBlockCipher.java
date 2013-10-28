/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * ����/����� Ű ��� ��ȣ ��ȣ ������ �����ؾ� �� �������̽�
 */
public interface AsymmetricBlockCipher {

	/**
	 * ���� �ʱ�ȭ �ÿ� ȣ���Ѵ�.
	 *  
	 * @param forEncryption ��ȣȭ ����, <code>true</code>�� ��ȣȭ, 
	 *                      <code>false</code>�� ��ȣȭ.
	 * @param params ó���� �ʿ��� Ű�� ��Ÿ �ʱ�ȭ �Ű�����
	 * @throws IllegalArgumentException ������ �ùٸ��� ���� ���
	 */
	public void init(boolean forEncryption, CipherParameters param);

	/**
	 * �Է� ��� ũ�⸦ ��ȯ�Ѵ�.
	 * 
	 * @return �Է� ��� ũ��
	 */
	public int getInputBlockSize();

	/**
	 * ��� ��� ũ�⸦ ��ȯ�Ѵ�.
	 * 
	 * @return ��� ��� ũ��
	 */
	public int getOutputBlockSize();

	/**
	 * �Ű������� ���� ��Ͽ� ���� ó���� �����Ѵ�.
	 * 
	 * @param in �Է� ��� ����Ʈ �迭
	 * @param inOff �Է� ��� ����Ʈ ��ġ
	 * @param len �Է� ��� ����Ʈ ũ��
	 * @return ��� ��� ����Ʈ �迭
	 * @throws InvalidCipherTextException ��� ��ȣȭ ó�� ���� ������ �߻��� ���
	 */
	public byte[] processBlock(byte[] in, int inOff, int len) 
			throws InvalidCipherTextException;

}
