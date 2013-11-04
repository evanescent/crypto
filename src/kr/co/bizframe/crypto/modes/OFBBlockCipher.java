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
 * OFB(Output-FeedBack) ��� ��忡 ���� ����
 */
public class OFBBlockCipher implements BlockCipher {
	private byte[] IV;
	private byte[] ofbV;
	private byte[] ofbOutV;

	private final int blockSize;
	private final BlockCipher cipher;

	/**
	 * �⺻ ������
	 *
	 * @param cipher ��� ��� ��ȣȭ ����
	 * @param blockSize ���� ��� ũ�� (��Ʈ)
	 */
	public OFBBlockCipher(BlockCipher cipher, int blockSize) {
		this.cipher = cipher;
		this.blockSize = blockSize / 8;

		this.IV = new byte[cipher.getBlockSize()];
		this.ofbV = new byte[cipher.getBlockSize()];
		this.ofbOutV = new byte[cipher.getBlockSize()];
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
	public void init(boolean encrypting, // ���õ�.
			CipherParameters params) throws IllegalArgumentException {
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
	 * @return ��� ��ȣ �˰���� + "/OFB" + ��� ũ��(��Ʈ) 
	 */
	public String getAlgorithmName() {
		return cipher.getAlgorithmName() + "/OFB" + (blockSize * 8);
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
		if ((inOff + blockSize) > in.length) {
			throw new DataLengthException("input buffer too short");
		}

		if ((outOff + blockSize) > out.length) {
			throw new DataLengthException("output buffer too short");
		}

		cipher.processBlock(ofbV, 0, ofbOutV, 0);

		//
		// XOR the ofbV with the plaintext producing the cipher text (and
		// the next input block).
		//
		for (int i = 0; i < blockSize; i++) {
			out[outOff + i] = (byte) (ofbOutV[i] ^ in[inOff + i]);
		}

		//
		// change over the input block.
		//
		System.arraycopy(ofbV, blockSize, ofbV, 0, ofbV.length - blockSize);
		System.arraycopy(ofbOutV, 0, ofbV, ofbV.length - blockSize, blockSize);

		return blockSize;
	}

	/**
	 * IV�� ��� ��ȣ ������ �ʱ�ȭ ������ �ǵ�����.
	 */
	public void reset() {
		System.arraycopy(IV, 0, ofbV, 0, IV.length);

		cipher.reset();
	}
}
