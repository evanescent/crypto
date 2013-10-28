/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * �ؽ� �Լ��� ������ �⺻ �������̽�
 */
public interface Digest {

	/**
	 * �˰������ ��ȯ�Ѵ�.
	 *  
	 * @return �˰����
	 */
	public String getAlgorithmName();

	/**
	 * �ؽ� ��� ũ�⸦ ��ȯ�Ѵ�.
	 * 
	 * @return �ؽ� ��� ũ��
	 */
	public int getDigestSize();

	/**
	 * �־��� ����Ʈ�� ������Ʈ�Ѵ�.
	 * 
	 * @param in �Է� ����Ʈ
	 */
	public void update(byte in);

	/**
	 * �־��� ����Ʈ �迭�� ������Ʈ�Ѵ�.
	 * 
	 * @param in �Է� ����Ʈ �迭
	 * @param inOff �Է� ����Ʈ ��ġ
	 * @param len �Է� ����Ʈ ����
	 */
	public void update(byte[] in, int inOff, int len);

	/**
	 * �־��� ����Ʈ �迭�� ����� ����Ѵ�.
	 * 
	 * @param out ��� ����Ʈ �迭
	 * @param outOff ��� ����Ʈ ��ġ
	 * @return ó���� ����Ʈ �迭 ũ��
	 */
	public int doFinal(byte[] out, int outOff);

	/**
	 * ���¸� �ʱ�ȭ ������ ������.
	 */
	public void reset();

}
