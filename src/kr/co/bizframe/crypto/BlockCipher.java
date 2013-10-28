/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * ��� ��ȣ ������ �����ؾ� �� �������̽�
 */
public interface BlockCipher {

	/**
	 * ���� �ʱ�ȭ �ÿ� ȣ���Ѵ�.
	 *  
	 * @param forEncryption ��ȣȭ ����, <code>true</code>�� ��ȣȭ, 
	 *                      <code>false</code>�� ��ȣȭ.
	 * @param params ó���� �ʿ��� Ű�� ��Ÿ �ʱ�ȭ �Ű�����
	 * @throws IllegalArgumentException ������ �ùٸ��� ���� ���
	 */
	public void init(boolean forEncryption, CipherParameters params)
			throws IllegalArgumentException;

	/**
	 * �˰������ ��ȯ�Ѵ�.
	 * 
	 * @return �˰����
	 */
	public String getAlgorithmName();

	/**
	 * ��� ũ�⸦ ��ȯ�Ѵ�.
	 * 
	 * @return ��� ũ��
	 */
	public int getBlockSize();

	/**
	 * �Ű������� ���� ��Ͽ� ���� ó���� �����Ѵ�.
	 * 
	 * @param in �Է� ��� ����Ʈ �迭
	 * @param inOff �Է� ��� ����Ʈ ��ġ
	 * @param out ��� ��� ����Ʈ �迭
	 * @param outOff ��� ��� ����Ʈ ��ġ
	 * @return ó���� ��� ����Ʈ ũ��
	 * @throws DataLengthException ��� ���̰� �ùٸ��� ���� ���
	 * @throws IllegalStateException ó�� ���°� �ùٸ��� ���� ���
	 */
	public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
			throws DataLengthException, IllegalStateException;

	/**
	 * ���¸� �ʱ�ȭ ������ ������.
	 */
	public void reset();

}
