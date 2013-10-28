/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.digests;

import kr.co.bizframe.crypto.Digest;

/**
 * {@link kr.co.bizframe.crypto.Digest}�� ���� Ŭ����
 */
public class DigestManager {

	private Digest digest;

	/**
	 * 
	 * 
	 * @param digest Digest ���� �������̽�
	 */
	public DigestManager(Digest digest) {
		this.digest = digest;
	}

	/**
	 * �ؽ��Լ��� ��� ũ�⸦ ��ȯ�Ѵ�.
	 * 
	 * @return �ؽ��Լ��� ��� ũ��
	 */
	public int getDigestSize() {
		return digest.getDigestSize();
	}

	/**
	 * �־��� ����Ʈ�� ������Ʈ�Ѵ�.
	 * 
	 * @param in �Է� ����Ʈ
	 */
	public void update(byte in) {
		digest.update(in);
	}

	/**
	 * �־��� ����Ʈ �迭�� ������Ʈ�Ѵ�.
	 * 
	 * @param in �Է� ����Ʈ �迭
	 * @param inOff �Է� ����Ʈ ��ġ
	 * @param len �Է� ����Ʈ ����
	 */
	public void update(byte[] in, int inOff, int len) {
		digest.update(in, inOff, len);
	}

	/**
	 * ����� ��ȯ�Ѵ�.
	 * 
	 * @return byte[] ��� ����Ʈ �迭
	 */
	public byte[] digest() {
		byte[] digestBytes = new byte[digest.getDigestSize()];
		digest.doFinal(digestBytes, 0);
		return digestBytes;
	}

	/**
	 * ���¸� �ʱ�ȭ ������ ������.
	 */
	public void reset() {
		digest.reset();
	}

}
