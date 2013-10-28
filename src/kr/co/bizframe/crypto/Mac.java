/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * �޽��� ���� �ڵ�(MACs)�� ������ �⺻ �������̽�
 */
public interface Mac {

	/**
	 * �޽��� ���� �ڵ� �ʱ�ȭ �ÿ� ȣ���Ѵ�.
	 * 
	 * @param params ó���� �ʿ��� Ű�� ��Ÿ �ʱ�ȭ �Ű�����
	 * @throws IllegalArgumentException ������ �ùٸ��� ���� ���
	 */
	public void init(CipherParameters params) throws IllegalArgumentException;

	/**
	 * �˰������ ��ȯ�Ѵ�.
	 *  
	 * @return �˰����
	 */
	public String getAlgorithmName();

	/**
	 * �޽��� ���� �ڵ� ��� ũ�⸦ ��ȯ�Ѵ�.
	 * 
	 * @return �޽��� ���� �ڵ� ��� ũ��
	 */
	public int getMacSize();

	/**
	 * �־��� ����Ʈ�� ������Ʈ�Ѵ�.
	 * 
	 * @param in �Է� ����Ʈ
	 * @throws IllegalStateException ó�� ���°� �ùٸ��� ���� ���
	 */
	public void update(byte in) throws IllegalStateException;

	/**
	 * �־��� ����Ʈ �迭�� ������Ʈ�Ѵ�.
	 * 
	 * @param in �Է� ����Ʈ �迭
	 * @param inOff �Է� ����Ʈ ��ġ
	 * @param len �Է� ����Ʈ ����
	 * @throws DataLengthException ��� ���̰� �ùٸ��� ���� ���
	 * @throws IllegalStateException ó�� ���°� �ùٸ��� ���� ���
	 */
	public void update(byte[] in, int inOff, int len)
			throws DataLengthException, IllegalStateException;

	/**
	 * �־��� ����Ʈ �迭�� ����� ����Ѵ�.
	 * 
	 * @param out ��� ����Ʈ �迭
	 * @param outOff ��� ����Ʈ ��ġ
	 * @return ó���� ����Ʈ �迭 ũ��
	 * @throws DataLengthException ��� ���̰� �ùٸ��� ���� ���
	 * @throws IllegalStateException ó�� ���°� �ùٸ��� ���� ���
	 */
	public int doFinal(byte[] out, int outOff) throws DataLengthException,
			IllegalStateException;

	/**
	 * ���¸� �ʱ�ȭ ������ ������.
	 */
	public void reset();
	
}
