/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.ciphers;

import java.math.BigInteger;

import kr.co.bizframe.crypto.CipherParameters;
import kr.co.bizframe.crypto.DataLengthException;
import kr.co.bizframe.crypto.params.ParametersWithRandom;
import kr.co.bizframe.crypto.params.RSAKeyParameters;
import kr.co.bizframe.crypto.params.RSAPrivateCrtKeyParameters;

/**
 * RSA 기본 구현 엔진
 */
class RSACoreEngine {

	private RSAKeyParameters key;
	private boolean forEncryption;

	/**
	 * 엔진 초기화 시에 호출한다.
	 *  
	 * @param forEncryption 암호화 여부, <code>true</code>면 암호화, 
	 *                      <code>false</code>면 복호화.
	 * @param params 처리에 필요한 키와 기타 초기화 매개변수
	 */
	public void init(boolean forEncryption, CipherParameters param) {

		if (param instanceof ParametersWithRandom) {
			ParametersWithRandom rParam = (ParametersWithRandom) param;

			key = (RSAKeyParameters) rParam.getParameters();
		} else {
			key = (RSAKeyParameters) param;
		}

		this.forEncryption = forEncryption;
	}

	/**
	 * 입력 블록의 최대 크기를 반환한다.
	 * 암호화 시에는 항상 키 길이보다 1 바이트가 작고,
	 * 복호화 시에는 키 길이와 같다.
	 *
	 * @return 입력 블록의 최대 크기
	 */
	public int getInputBlockSize() {
		int bitSize = key.getModulus().bitLength();

		if (forEncryption) {
			return (bitSize + 7) / 8 - 1;
		} else {
			return (bitSize + 7) / 8;
		}
	}

	/**
	 * 출력 블록의 최대 크기를 반환한다.
	 * 복호화 시에는 항상 키 길이보다 1 바이트가 작고,
	 * 암호화 시에는 키 길이와 같다.
	 *
	 * @return 출력 블록의 최대 크기
	 */
	public int getOutputBlockSize() {
		int bitSize = key.getModulus().bitLength();

		if (forEncryption) {
			return (bitSize + 7) / 8;
		} else {
			return (bitSize + 7) / 8 - 1;
		}
	}

	/**
	 * 입력 바이트 배열을 정수로 변환한다.
	 * 
	 * @param in 입력 바이트 배열
	 * @param inOff 입력 바이트 위치
	 * @param inLen 입력 바이트 길이
	 * @return 변환된 정수
	 * @throws DataLengthException 입력 바이트 배열의 길이가 너무 큰 경우
	 */
	public BigInteger convertInput(byte[] in, int inOff, int inLen) {
		if (inLen > (getInputBlockSize() + 1)) {
			throw new DataLengthException("input too large for RSA cipher.");
		} else if (inLen == (getInputBlockSize() + 1) && !forEncryption) {
			throw new DataLengthException("input too large for RSA cipher.");
		}

		byte[] block;

		if (inOff != 0 || inLen != in.length) {
			block = new byte[inLen];

			System.arraycopy(in, inOff, block, 0, inLen);
		} else {
			block = in;
		}

		BigInteger res = new BigInteger(1, block);
		if (res.compareTo(key.getModulus()) >= 0) {
			throw new DataLengthException("input too large for RSA cipher.");
		}

		return res;
	}

	/**
	 * 입력 정수를 바이트 배열로 변환한다.
	 * 
	 * @param result 입력 정수
	 * @return 변환된 바이트 배열
	 */
	public byte[] convertOutput(BigInteger result) {
		byte[] output = result.toByteArray();

		if (forEncryption) {
			// have ended up with an extra zero byte, copy down.
			if (output[0] == 0 && output.length > getOutputBlockSize()) 
			{
				byte[] tmp = new byte[output.length - 1];

				System.arraycopy(output, 1, tmp, 0, tmp.length);

				return tmp;
			}

			if (output.length < getOutputBlockSize()) // have ended up with less
														// bytes than normal,
														// lengthen
			{
				byte[] tmp = new byte[getOutputBlockSize()];

				System.arraycopy(output, 0, tmp, tmp.length - output.length,
						output.length);

				return tmp;
			}
		} else {
			if (output[0] == 0) // have ended up with an extra zero byte, copy down.
			{
				byte[] tmp = new byte[output.length - 1];

				System.arraycopy(output, 1, tmp, 0, tmp.length);

				return tmp;
			}
		}

		return output;
	}

	/**
	 * 입력 정수에 대해 RSA 처리를 진행한다.
	 * 
	 * @param input 입력 정수
	 * @return 출력 정수
	 */
	public BigInteger processBlock(BigInteger input) {
		if (key instanceof RSAPrivateCrtKeyParameters) {
			//
			// we have the extra factors, use the Chinese Remainder Theorem -
			// the author
			// wishes to express his thanks to Dirk Bonekaemper at rtsffm.com
			// for
			// advice regarding the expression of this.
			//
			RSAPrivateCrtKeyParameters crtKey = (RSAPrivateCrtKeyParameters) key;

			BigInteger p = crtKey.getP();
			BigInteger q = crtKey.getQ();
			BigInteger dP = crtKey.getDP();
			BigInteger dQ = crtKey.getDQ();
			BigInteger qInv = crtKey.getQInv();

			BigInteger mP, mQ, h, m;

			// mP = ((input mod p) ^ dP)) mod p
			mP = (input.remainder(p)).modPow(dP, p);

			// mQ = ((input mod q) ^ dQ)) mod q
			mQ = (input.remainder(q)).modPow(dQ, q);

			// h = qInv * (mP - mQ) mod p
			h = mP.subtract(mQ);
			h = h.multiply(qInv);
			h = h.mod(p); // mod (in Java) returns the positive residual

			// m = h * q + mQ
			m = h.multiply(q);
			m = m.add(mQ);

			return m;
		} else {
			return input.modPow(key.getExponent(), key.getModulus());
		}
	}
}
