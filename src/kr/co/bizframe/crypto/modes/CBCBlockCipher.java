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
 * CBC(Cipher-Block-Chaining) 운용 모드에 대한 구현
 */
public class CBCBlockCipher implements BlockCipher {

	private byte[] IV;
	private byte[] cbcV;
	private byte[] cbcNextV;

	private int blockSize;
	private BlockCipher cipher = null;
	private boolean encrypting;

	/**
	 * 기본 생성자
	 *
	 * @param cipher 대상 블록 암호화 엔진
	 */
	public CBCBlockCipher(BlockCipher cipher) {
		this.cipher = cipher;
		this.blockSize = cipher.getBlockSize();

		this.IV = new byte[blockSize];
		this.cbcV = new byte[blockSize];
		this.cbcNextV = new byte[blockSize];
	}

	/**
	 * 블록 암호 엔진을 반환한다.
	 *
	 * @return 블록 암호 엔진
	 */
	public BlockCipher getUnderlyingCipher() {
		return cipher;
	}

	/**
	 * 엔진 초기화 시에 호출한다. IV가 없다면 '0'(zero)를 사용한다.
	 *  
	 * @param forEncryption 암호화 여부, <code>true</code>면 암호화, 
	 *                      <code>false</code>면 복호화.
	 * @param params 처리에 필요한 키와 기타 초기화 매개변수
	 * @throws IllegalArgumentException 설정이 올바르지 않은 경우
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
	 * 알고리즘명과 운용모드를 반환한다.
	 *
	 * @return 블록 암호 알고리즘명 + "/CBC"
	 */
	public String getAlgorithmName() {
		return cipher.getAlgorithmName() + "/CBC";
	}

	/**
	 * 블록 암호의 블록 크기를 반환한다.
	 * 
	 * @return 블록 암호의 블록 크기
	 */
	public int getBlockSize() {
		return cipher.getBlockSize();
	}

	/**
	 * 주어진 입/출력 바이트 배열을 사용해 처리한다.
	 *
	 * @param in 입력 바이트 배열
	 * @param inOff 입력 바이트 위치
	 * @param out 출력 바이트 배열
	 * @param outOff 출력 바이트 위치
	 * @exception DataLengthException 바이트 배열이 충분치 않은 경우
	 * @exception IllegalStateException 초기화되지 않은 경우
	 * @return 처리된 바이트 배열의 길이
	 */
	public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
			throws DataLengthException, IllegalStateException {
		return (encrypting) ? encryptBlock(in, inOff, out, outOff)
				: decryptBlock(in, inOff, out, outOff);
	}

	/**
	 * IV와 블록 암호 엔진을 초기화 전으로 되돌린다.
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
