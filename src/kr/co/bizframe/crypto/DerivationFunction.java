/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * base interface for general purpose byte derivation functions.
 */
public interface DerivationFunction {
	public void init(DerivationParameters param);

	/**
	 * return the message digest used as the basis for the function
	 */
	public Digest getDigest();

	public int generateBytes(byte[] out, int outOff, int len)
			throws DataLengthException, IllegalArgumentException;

}
