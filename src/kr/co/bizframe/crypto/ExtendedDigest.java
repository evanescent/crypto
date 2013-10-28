/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

public interface ExtendedDigest extends Digest {

	/**
	 * Return the size in bytes of the internal buffer the digest applies it's
	 * compression function to.
	 *
	 * @return byte length of the digests internal buffer.
	 */
	public int getByteLength();
}
