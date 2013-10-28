/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.modes;

import kr.co.bizframe.crypto.BlockCipher;
import kr.co.bizframe.crypto.CipherParameters;
import kr.co.bizframe.crypto.DataLengthException;
import kr.co.bizframe.crypto.params.ParametersWithIV;
import kr.co.bizframe.crypto.util.Arrays;

/**
 * CBC(Cipher-Block-Chaining) ��� ��忡 ���� ����
 */
public class CBCBlockCipher implements BlockCipher {

	private byte[] IV;
	private byte[] cbcV;
	private byte[] cbcNextV;

	private int blockSize;
	private BlockCipher cipher = null;
	private boolean encrypting;

	/**
	 * �⺻ ������
	 *
	 * @param cipher ��� ��� ��ȣȭ ����
	 */
	public CBCBlockCipher(BlockCipher cipher) {
		this.cipher = cipher;
		this.blockSize = cipher.getBlockSize();

		this.IV = new byte[blockSize];
		this.cbcV = new byte[blockSize];
		this.cbcNextV = new byte[blockSize];
	}

	/**
	 * ��� ��ȣ ������ ��ȯ�Ѵ�.
	 *
	 * @return ��� ��ȣ ����
	 */
	public BlockCipher getUnderlyingCipher() {
		return cipher;
	}

	/**
	 * ���� �ʱ�ȭ �ÿ� ȣ���Ѵ�. IV�� ���ٸ� '0'(zero)�� ����Ѵ�.
	 *  
	 * @param forEncryption ��ȣȭ ����, <code>true</code>�� ��ȣȭ, 
	 *                      <code>false</code>�� ��ȣȭ.
	 * @param params ó���� �ʿ��� Ű�� ��Ÿ �ʱ�ȭ �Ű�����
	 * @throws IllegalArgumentException ������ �ùٸ��� ���� ���
	 */
	public void init(boolean encrypting, CipherParameters params)
			throws IllegalArgumentException {
		this.encrypting = encrypting;

		if (params instanceof ParametersWithIV) {
			ParametersWithIV ivParam = (ParametersWithIV) params;
			byte[] iv = ivParam.getIV();

			if (iv.length != blockSize) {
				throw new IllegalArgumentException(
						"initialisation vector must be the same length as block size");
			}

			System.arraycopy(iv, 0, IV, 0, iv.length);

			reset();

			cipher.init(encrypting, ivParam.getParameters());
		} else {
			reset();

			cipher.init(encrypting, params);
		}
	}

	/**
	 * �˰����� ����带 ��ȯ�Ѵ�.
	 *
	 * @return ��� ��ȣ �˰���� + "/CBC"
	 */
	public String getAlgorithmName() {
		return cipher.getAlgorithmName() + "/CBC";
	}

	/**
	 * ��� ��ȣ�� ��� ũ�⸦ ��ȯ�Ѵ�.
	 * 
	 * @return ��� ��ȣ�� ��� ũ��
	 */
	public int getBlockSize() {
		return cipher.getBlockSize();
	}

	/**
	 * �־��� ��/��� ����Ʈ �迭�� ����� ó���Ѵ�.
	 *
	 * @param in �Է� ����Ʈ �迭
	 * @param inOff �Է� ����Ʈ ��ġ
	 * @param out ��� ����Ʈ �迭
	 * @param outOff ��� ����Ʈ ��ġ
	 * @exception DataLengthException ����Ʈ �迭�� ���ġ ���� ���
	 * @exception IllegalStateException �ʱ�ȭ���� ���� ���
	 * @return ó���� ����Ʈ �迭�� ����
	 */
	public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
			throws DataLengthException, IllegalStateException {
		return (encrypting) ? encryptBlock(in, inOff, out, outOff)
				: decryptBlock(in, inOff, out, outOff);
	}

	/**
	 * IV�� ��� ��ȣ ������ �ʱ�ȭ ������ �ǵ�����.
	 */
	public void reset() {
		System.arraycopy(IV, 0, cbcV, 0, IV.length);
		Arrays.fill(cbcNextV, (byte) 0);

		cipher.reset();
	}

	private int encryptBlock(byte[] in, int inOff, byte[] out, int outOff)
			throws DataLengthException, IllegalStateException {
		if ((inOff + blockSize) > in.length) {
			throw new DataLengthException("input buffer too short");
		}

		/*
		 * XOR the cbcV and the input, then encrypt the cbcV
		 */
		for (int i = 0; i < blockSize; i++) {
			cbcV[i] ^= in[inOff + i];
		}

		int length = cipher.processBlock(cbcV, 0, out, outOff);

		/*
		 * copy ciphertext to cbcV
		 */
		System.arraycopy(out, outOff, cbcV, 0, cbcV.length);

		return length;
	}

	private int decryptBlock(byte[] in, int inOff, byte[] out, int outOff)
			throws DataLengthException, IllegalStateException {
		if ((inOff + blockSize) > in.length) {
			throw new DataLengthException("input buffer too short");
		}

		System.arraycopy(in, inOff, cbcNextV, 0, blockSize);

		int length = cipher.processBlock(in, inOff, out, outOff);

		/*
		 * XOR the cbcV and the output
		 */
		for (int i = 0; i < blockSize; i++) {
			out[outOff + i] ^= cbcV[i];
		}

		/*
		 * swap the back up buffer into next position
		 */
		byte[] tmp;

		tmp = cbcV;
		cbcV = cbcNextV;
		cbcNextV = tmp;

		return length;
	}
}
