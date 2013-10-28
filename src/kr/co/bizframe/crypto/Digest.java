/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 *  digest 구현 기본 인터페이스
 */
public interface Digest {

	public String getAlgorithmName();

	public int getDigestSize();

	public void update(byte in);

	public void update(byte[] in, int inOff, int len);

	public int doFinal(byte[] out, int outOff);

	public void reset();

}
