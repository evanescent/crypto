/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * �Ϲ����� ������ ����Ʈ �迭 �����Լ�(Derivation Function; DF)�� ���� �������̽�
 */
public interface DerivationFunction {
	
	/**
	 * �־��� �Ű������� ����� �ʱ�ȭ�Ѵ�.
	 * 
	 * @param param �ʱ�ȭ�� ����� �Ű�����
	 */
	public void init(DerivationParameters param);

	/**
	 * �����Լ��� ����� �ؽ��Լ��� ��ȯ�Ѵ�.
	 */
	public Digest getDigest();

	/**
	 * ����Ʈ �迭�� ������ ��ȯ�Ѵ�.
	 *  
	 * @param out ��� ����Ʈ �迭
	 * @param outOff ��� ��� ����Ʈ ��ġ
	 * @param len ������ ����Ʈ ����
	 * @return ������ ����Ʈ �迭�� ����
	 * @throws DataLengthException ��� ���̰� �ùٸ��� ���� ���
	 * @throws IllegalStateException ó�� ���°� �ùٸ��� ���� ���
	 */
	public int generateBytes(byte[] out, int outOff, int len) 
			throws DataLengthException, IllegalArgumentException;

}
