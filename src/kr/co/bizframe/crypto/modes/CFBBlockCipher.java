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

/**
 * CFB(Cipher-FeedBack) ��� ��忡 ���� ����
 */
public class CFBBlockCipher implements BlockCipher {
	private byte[] IV;
	private byte[] cfbV;
	private byte[] cfbOutV;

	private int blockSize;
	private BlockCipher cipher = null;
	private boolean encrypting;

	/**
	 * �⺻ ������
	 *
	 * @param cipher ��� ��� ��ȣȭ ����
	 * @param bitBlockSize ���� ��� ũ�� (��Ʈ)
	 */
	public CFBBlockCipher(BlockCipher cipher, int bitBlockSize) {
		this.cipher = cipher;
		this.blockSize = bitBlockSize / 8;

		this.IV = new byte[cipher.getBlockSize()];
		this.cfbV = new byte[cipher.getBlockSize()];
		this.cfbOutV = new byte[cipher.getBlockSize()];
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

			if (iv.length < IV.length) {
				// prepend the supplied IV with zeros (per FIPS PUB 81)
				System.arraycopy(iv, 0, IV, IV.length - iv.length, iv.length);
				for (int i = 0; i < IV.length - iv.length; i++) {
					IV[i] = 0;
				}
			} else {
				System.arraycopy(iv, 0, IV, 0, IV.length);
			}

			reset();

			cipher.init(true, ivParam.getParameters());
		} else {
			reset();

			cipher.init(true, params);
		}
	}

	/**
	 * �˰����� ����带 ��ȯ�Ѵ�.
	 *
	 * @return ��� ��ȣ �˰���� + "/CFB" + ��� ũ��(��Ʈ)
	 */
	public String getAlgorithmName() {
		return cipher.getAlgorithmName() + "/CFB" + (blockSize * 8);
	}

	/**
	 * ��� ��ȣ�� ��� ũ�⸦ ��ȯ�Ѵ�.
	 * 
	 * @return ��� ��ȣ�� ��� ũ��
	 */
	public int getBlockSize() {
		return blockSize;
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
	
	private int encryptBlock(byte[] in, int inOff, byte[] out, int outOff)
			throws DataLengthException, IllegalStateException {
		if ((inOff + blockSize) > in.length) {
			throw new DataLengthException("input buffer too short");
		}

		if ((outOff + blockSize) > out.length) {
			throw new DataLengthException("output buffer too short");
		}

		cipher.processBlock(cfbV, 0, cfbOutV, 0);

		//
		// XOR the cfbV with the plaintext producing the ciphertext
		//
		for (int i = 0; i < blockSize; i++) {
			out[outOff + i] = (byte) (cfbOutV[i] ^ in[inOff + i]);
		}

		//
		// change over the input block.
		//
		System.arraycopy(cfbV, blockSize, cfbV, 0, cfbV.length - blockSize);
		System.arraycopy(out, outOff, cfbV, cfbV.length - blockSize, blockSize);

		return blockSize;
	}
	
	private int decryptBlock(byte[] in, int inOff, byte[] out, int outOff)
			throws DataLengthException, IllegalStateException {
		if ((inOff + blockSize) > in.length) {
			throw new DataLengthException("input buffer too short");
		}

		if ((outOff + blockSize) > out.length) {
			throw new DataLengthException("output buffer too short");
		}

		cipher.processBlock(cfbV, 0, cfbOutV, 0);

		//
		// change over the input block.
		//
		System.arraycopy(cfbV, blockSize, cfbV, 0, cfbV.length - blockSize);
		System.arraycopy(in, inOff, cfbV, cfbV.length - blockSize, blockSize);

		//
		// XOR the cfbV with the ciphertext producing the plaintext
		//
		for (int i = 0; i < blockSize; i++) {
			out[outOff + i] = (byte) (cfbOutV[i] ^ in[inOff + i]);
		}

		return blockSize;
	}

	/**
	 * IV�� ��� ��ȣ ������ �ʱ�ȭ ������ �ǵ�����.
	 */
	public void reset() {
		System.arraycopy(IV, 0, cfbV, 0, IV.length);

		cipher.reset();
	}
}
