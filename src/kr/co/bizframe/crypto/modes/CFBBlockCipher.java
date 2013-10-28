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
 * CFB(Cipher-FeedBack) 운용 모드에 대한 구현
 */
public class CFBBlockCipher implements BlockCipher {
	private byte[] IV;
	private byte[] cfbV;
	private byte[] cfbOutV;

	private int blockSize;
	private BlockCipher cipher = null;
	private boolean encrypting;

	/**
	 * 기본 생성자
	 *
	 * @param cipher 대상 블록 암호화 엔진
	 * @param bitBlockSize 단위 블록 크기 (비트)
	 */
	public CFBBlockCipher(BlockCipher cipher, int bitBlockSize) {
		this.cipher = cipher;
		this.blockSize = bitBlockSize / 8;

		this.IV = new byte[cipher.getBlockSize()];
		this.cfbV = new byte[cipher.getBlockSize()];
		this.cfbOutV = new byte[cipher.getBlockSize()];
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
	 * 알고리즘명과 운용모드를 반환한다.
	 *
	 * @return 블록 암호 알고리즘명 + "/CFB" + 블록 크기(비트)
	 */
	public String getAlgorithmName() {
		return cipher.getAlgorithmName() + "/CFB" + (blockSize * 8);
	}

	/**
	 * 블록 암호의 블록 크기를 반환한다.
	 * 
	 * @return 블록 암호의 블록 크기
	 */
	public int getBlockSize() {
		return blockSize;
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
	 * IV와 블록 암호 엔진을 초기화 전으로 되돌린다.
	 */
	public void reset() {
		System.arraycopy(IV, 0, cfbV, 0, IV.length);

		cipher.reset();
	}
}
