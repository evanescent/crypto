/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * {@link kr.co.bizframe.crypto.BlockCipher}�� ���� ���� Ŭ����
 */
public class BufferedBlockCipher {

	protected byte[] buf;
	protected int bufOff;

	protected boolean forEncryption;
	protected BlockCipher cipher;

	protected boolean partialBlockOkay;
	protected boolean pgpCFB;

	/**
	 * ����Ŭ������ ���� �⺻ ������
	 */
	protected BufferedBlockCipher() {
	}

	/**
	 * �е��� �������� ���� ���� ��� ��ȣ ��¡�� �����Ѵ�.
	 * 
	 * @param cipher ���۸��� ������ ��� ��ȣ ����
	 */
	public BufferedBlockCipher(BlockCipher cipher) {

		this.cipher = cipher;

		buf = new byte[cipher.getBlockSize()];
		bufOff = 0;

		//
		// check if we can handle partial blocks on doFinal.
		//
		String name = cipher.getAlgorithmName();
		int idx = name.indexOf('/') + 1;

		pgpCFB = (idx > 0 && name.startsWith("PGP", idx));

		if (pgpCFB) {
			partialBlockOkay = true;
		} else {
			partialBlockOkay = (idx > 0 && (name.startsWith("CFB", idx)
					|| name.startsWith("OFB", idx)
					|| name.startsWith("OpenPGP", idx)
					|| name.startsWith("SIC", idx) || name.startsWith("GCTR",
					idx)));
		}
	}

	/**
	 * ������ ��� ��ȣ ������ ��ȯ�Ѵ�.
	 * 
	 * @return ������ ��� ��ȣ ������ ��ȯ
	 */
	public BlockCipher getUnderlyingCipher() {
		return cipher;
	}

	/**
	 * ���� �ʱ�ȭ �ÿ� ȣ���Ѵ�.
	 *  
	 * @param forEncryption ��ȣȭ ����, <code>true</code>�� ��ȣȭ, 
	 *                      <code>false</code>�� ��ȣȭ.
	 * @param params ó���� �ʿ��� Ű�� ��Ÿ �ʱ�ȭ �Ű�����
	 * @throws IllegalArgumentException ������ �ùٸ��� ���� ���
	 */
	public void init(boolean forEncryption, CipherParameters params)
			throws IllegalArgumentException {
		this.forEncryption = forEncryption;
		reset();
		cipher.init(forEncryption, params);
	}

	/**
	 * ��� ũ�⸦ ��ȯ�Ѵ�.
	 * 
	 * @return ��� ũ��
	 */
	public int getBlockSize() {
		return cipher.getBlockSize();
	}

	/**
	 * ������Ʈ �� �Է� ����Ʈ �迭�� ���̷κ��� �ʿ��� ��� ������ ũ�⸦ ��ȯ�Ѵ�.
	 * 
	 * @param len �Է� ����Ʈ �迭�� ũ��
	 * @return ������Ʈ�� �ʿ��� ��� ������ ũ��
	 */
	public int getUpdateOutputSize(int len) {

		int total = len + bufOff;
		int leftOver;

		if (pgpCFB) {
			leftOver = total % buf.length - (cipher.getBlockSize() + 2);
		} else {
			leftOver = total % buf.length;
		}

		return total - leftOver;
	}

	/**
	 * �־��� ���̿� ��� ���۸� ���� ���̸� ��ȯ�Ѵ�.
	 * 
	 * @param length �Է� ����
	 * @return �־��� ���̿� ��� ���۸� ���� ����
	 */
	public int getOutputSize(int length) {
		return length + bufOff;
	}

	/**
	 * ���� ����Ʈ�� ���� ó���� �����Ѵ�.
	 * 
	 * @param in �Է� ����Ʈ
	 * @param out ��� ����Ʈ �迭
	 * @param outOff ��� ����Ʈ ��ġ
	 * @return ��� ����Ʈ ����� ����� ����
	 * @exception DataLengthException ��� ����Ʈ �迭�� ���ġ ���� ���
	 * @exception IllegalStateException �ʱ�ȭ���� ���� ���
	 */
	public int processByte(byte in, byte[] out, int outOff)
			throws DataLengthException, IllegalStateException {

		int resultLen = 0;

		buf[bufOff++] = in;

		if (bufOff == buf.length) {
			resultLen = cipher.processBlock(buf, 0, out, outOff);
			bufOff = 0;
		}

		return resultLen;
	}

	/**
	 * ����Ʈ �迭�� ���� ó���� �����Ѵ�.
	 * 
	 * @param in �Է� ����Ʈ �迭
	 * @param inOff �Է� ����Ʈ ��ġ
	 * @param out ��� ����Ʈ �迭
	 * @param outOff ��� ����Ʈ ��ġ
	 * @return ��� ����Ʈ ����� ����� ����
	 * @exception DataLengthException ��� ����Ʈ �迭�� ���ġ ���� ���
	 * @exception IllegalStateException �ʱ�ȭ���� ���� ���
	 */
	public int processBytes(byte[] in, int inOff, int len, byte[] out,
			int outOff) throws DataLengthException, IllegalStateException {

		if (len < 0) {
			throw new IllegalArgumentException(
					"Can't have a negative input length!");
		}

		int blockSize = getBlockSize();
		int length = getUpdateOutputSize(len);

		if (length > 0) {
			if ((outOff + length) > out.length) {
				throw new DataLengthException("output buffer too short");
			}
		}

		int resultLen = 0;
		int gapLen = buf.length - bufOff;

		if (len > gapLen) {
			System.arraycopy(in, inOff, buf, bufOff, gapLen);

			resultLen += cipher.processBlock(buf, 0, out, outOff);

			bufOff = 0;
			len -= gapLen;
			inOff += gapLen;

			while (len > buf.length) {
				resultLen += cipher.processBlock(in, inOff, out, outOff
						+ resultLen);

				len -= blockSize;
				inOff += blockSize;
			}
		}

		System.arraycopy(in, inOff, buf, bufOff, len);

		bufOff += len;

		if (bufOff == buf.length) {
			resultLen += cipher.processBlock(buf, 0, out, outOff + resultLen);
			bufOff = 0;
		}

		return resultLen;
	}

	/**
	 * ������ ������ ��Ͽ� ���� ó���� �����Ѵ�.
	 * 
	 * @param out ��� ����Ʈ �迭
	 * @param outOff ��� ����Ʈ �迭 ��ġ
	 * @return ��� ����Ʈ ����� ����� ����
	 * @exception DataLengthException ��� ����Ʈ �迭�� ���ġ ���� ���
	 * @exception IllegalStateException �ʱ�ȭ���� ���� ���
	 * @exception InvalidCipherTextException �е��� �������� �ʴ� ���
	 * @exception DataLengthException ��� ũ�Ⱑ ���� �ʴ� ���
	 */
	public int doFinal(byte[] out, int outOff) throws DataLengthException,
			IllegalStateException, InvalidCipherTextException {
		try {
			int resultLen = 0;

			if (outOff + bufOff > out.length) {
				throw new DataLengthException(
						"output buffer too short for doFinal()");
			}

			if (bufOff != 0) {
				if (!partialBlockOkay) {
					throw new DataLengthException("data not block size aligned");
				}

				cipher.processBlock(buf, 0, buf, 0);
				resultLen = bufOff;
				bufOff = 0;
				System.arraycopy(buf, 0, out, outOff, resultLen);
			}

			return resultLen;
		} finally {
			reset();
		}
	}

	/**
	 * 
	 */
	public void reset() {
		//
		// ���۸� ����.
		//
		for (int i = 0; i < buf.length; i++) {
			buf[i] = 0;
		}

		bufOff = 0;

		//
		// ��ȣȭ ������ �����Ѵ�.
		//
		cipher.reset();
	}
}
