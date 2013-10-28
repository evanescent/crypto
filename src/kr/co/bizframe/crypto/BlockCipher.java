/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * Block cipher engines are expected to conform to this interface.
 */
public interface BlockCipher {

	
	public void init(boolean forEncryption, CipherParameters params)
			throws IllegalArgumentException;

	public String getAlgorithmName();

	public int getBlockSize();

	public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
			throws DataLengthException, IllegalStateException;

	public void reset();

}
