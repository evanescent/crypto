/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.digests;

import kr.co.bizframe.crypto.ExtendedDigest;

/**
 * "Handbook of Applied Cryptography" pages 344 - 347 �� ���� �� MD4�� �⺻ �����̴�.
 */
public abstract class GeneralDigest implements ExtendedDigest {

	private static final int BYTE_LENGTH = 64;
	private byte[] xBuf;
	private int xBufOff;

	private long byteCount;

	/**
	 * �⺻ ������
	 */
	protected GeneralDigest() {
		xBuf = new byte[4];
		xBufOff = 0;
	}

	/**
	 * J2ME���� �������� �ʴ� Object.clone() �������̽� ��� �� �����ڸ� ����Ѵ�.
	 * @param GeneralDigest 
	 */
	protected GeneralDigest(GeneralDigest t) {
		xBuf = new byte[t.xBuf.length];
		System.arraycopy(t.xBuf, 0, xBuf, 0, t.xBuf.length);

		xBufOff = t.xBufOff;
		byteCount = t.byteCount;
	}

	/**
	 * �Ϻ�ȣȭ �����  byte ���·� Digest�� �����Ѵ�.
	 * @param in �Ϻ�ȣȭ ����� byte ������
	 */
	public void update(byte in) {
		xBuf[xBufOff++] = in;

		if (xBufOff == xBuf.length) {
			processWord(xBuf, 0);
			xBufOff = 0;
		}

		byteCount++;
	}

	/**
	 * 
	 * �Ϻ�ȣȭ �����  byte ���·� ������ inOff�κ��� �����Ͽ� Digest�� �����Ѵ�.
	 * @param in �Ϻ�ȣȭ ����� byte ������
	 * @param inOff ���� offset
	 * @param len ���Ǵ� ����Ʈ �� 
	 */
	public void update(byte[] in, int inOff, int len) {
		//
		// ���� �ܾ ä���.
		//
		while ((xBufOff != 0) && (len > 0)) {
			update(in[inOff]);

			inOff++;
			len--;
		}

		//
		// ��� �ܾ ó���Ѵ�.
		//
		while (len > xBuf.length) {
			processWord(in, inOff);

			inOff += xBuf.length;
			len -= xBuf.length;
			byteCount += xBuf.length;
		}

		//
		// ������ �ܾ �ε��Ų��.
		//
		while (len > 0) {
			update(in[inOff]);

			inOff++;
			len--;
		}
	}

	/**
	 * �е� ���� ���� ó���� �Ͽ� Digest�� �Ϸ��Ѵ�.
	 */
	public void finish() {
		long bitLength = (byteCount << 3);

		//
		// �е� ����Ʈ�� �߰��Ѵ�.
		//
		update((byte) 128);

		while (xBufOff != 0) {
			update((byte) 0);
		}

		processLength(bitLength);

		processBlock();
	}

	/**
	 * �ʱ�ȭ ��Ų��.
	 */
	public void reset() {
		byteCount = 0;

		xBufOff = 0;
		for (int i = 0; i < xBuf.length; i++) {
			xBuf[i] = 0;
		}
	}

	/**
	 * byte ���̸� ��ȯ�Ѵ�.
	 * @return byte ���� 64
	 */
	public int getByteLength() {
		return BYTE_LENGTH;
	}

	protected abstract void processWord(byte[] in, int inOff);

	protected abstract void processLength(long bitLength);

	protected abstract void processBlock();
}
