/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * �Ϲ����� ���ڼ���Ⱑ ������ �������̽�
 */
public interface Signer {

	/**
	 * �ʱ�ȭ �ÿ� ȣ���Ѵ�.
	 *  
	 * @param forSigning ���� ����, <code>true</code>�� ����, 
	 *                   <code>false</code>�� ����.
	 * @param param ó���� �ʿ��� Ű�� ��Ÿ �ʱ�ȭ �Ű�����
	 */
	public void init(boolean forSigning, CipherParameters param);

	/**
	 * �־��� ����Ʈ�� ������Ʈ�Ѵ�.
	 * 
	 * @param b �Է� ����Ʈ
	 */
	public void update(byte b);

	/**
	 * �־��� ����Ʈ �迭�� ������Ʈ�Ѵ�.
	 * 
	 * @param in �Է� ����Ʈ �迭
	 * @param off �Է� ����Ʈ ��ġ
	 * @param len �Է� ����Ʈ ����
	 */
	public void update(byte[] in, int off, int len);

	/**
	 * ���ڼ����� �����Ѵ�.
	 * 
	 * @return ������ ���ڼ��� ����Ʈ �迭
	 * @throws CryptoException ���� ���� ������ �߻��� ��� 
	 * @throws DataLengthException ������ ���̰� ���ġ ���� ���
	 */
	public byte[] generateSignature() throws CryptoException,
			DataLengthException;

	/**
	 * �־��� ���ڼ����� �����Ѵ�.
	 * 
	 * @return ���� ����� �ùٸ��ٸ� <code>true</code>, �ƴ϶�� <code>false</code>
	 */
	public boolean verifySignature(byte[] signature);

	/**
	 * ���� ���·� �ǵ�����.
	 */
	public void reset();
	
}
