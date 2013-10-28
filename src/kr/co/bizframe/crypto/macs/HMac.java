/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.macs;

import java.util.Hashtable;

import kr.co.bizframe.crypto.CipherParameters;
import kr.co.bizframe.crypto.Digest;
import kr.co.bizframe.crypto.ExtendedDigest;
import kr.co.bizframe.crypto.Mac;
import kr.co.bizframe.crypto.params.KeyParameter;


/**
 * HMAC implementation based on RFC2104
 *
 * H(K XOR opad, H(K XOR ipad, text))
 */
public class HMac implements Mac {

	private final static byte IPAD = (byte) 0x36;
	private final static byte OPAD = (byte) 0x5C;

	private Digest digest;
	private int digestSize;
	private int blockLength;

	private byte[] inputPad;
	private byte[] outputPad;

	private static Hashtable<String, Integer> blockLengths;

	static {
		blockLengths = new Hashtable<String, Integer>();
		blockLengths.put("MD5", new Integer(64));
		blockLengths.put("SHA1", new Integer(64));
		blockLengths.put("SHA256", new Integer(64));
		blockLengths.put("SHA384", new Integer(128));
		blockLengths.put("SHA512", new Integer(128));
	}

	private static int getByteLength(Digest digest) {
		if (digest instanceof ExtendedDigest) {
			return ((ExtendedDigest) digest).getByteLength();
		}

		Integer b = (Integer) blockLengths.get(digest.getAlgorithmName());

		if (b == null) {
			throw new IllegalArgumentException("unknown digest passed: "
					+ digest.getAlgorithmName());
		}

		return b.intValue();
	}

	/**
	 * Base constructor for one of the standard digest algorithms that the
	 * byteLength of the algorithm is know for.
	 *
	 * @param digest
	 *            the digest.
	 */
	public HMac(Digest digest) {
		this(digest, getByteLength(digest));
	}

	private HMac(Digest digest, int byteLength) {
		this.digest = digest;
		digestSize = digest.getDigestSize();

		this.blockLength = byteLength;

		inputPad = new byte[blockLength];
		outputPad = new byte[blockLength];
	}

	public String getAlgorithmName() {
		return digest.getAlgorithmName() + "/HMAC";
	}

	public Digest getUnderlyingDigest() {
		return digest;
	}

	public void init(CipherParameters params) {
		digest.reset();

		byte[] key = ((KeyParameter) params).getKey();

		if (key.length > blockLength) {
			digest.update(key, 0, key.length);
			digest.doFinal(inputPad, 0);
			for (int i = digestSize; i < inputPad.length; i++) {
				inputPad[i] = 0;
			}
		} else {
			System.arraycopy(key, 0, inputPad, 0, key.length);
			for (int i = key.length; i < inputPad.length; i++) {
				inputPad[i] = 0;
			}
		}

		outputPad = new byte[inputPad.length];
		System.arraycopy(inputPad, 0, outputPad, 0, inputPad.length);

		for (int i = 0; i < inputPad.length; i++) {
			inputPad[i] ^= IPAD;
		}

		for (int i = 0; i < outputPad.length; i++) {
			outputPad[i] ^= OPAD;
		}

		digest.update(inputPad, 0, inputPad.length);
	}

	public int getMacSize() {
		return digestSize;
	}

	public void update(byte in) {
		digest.update(in);
	}

	public void update(byte[] in, int inOff, int len) {
		digest.update(in, inOff, len);
	}

	public int doFinal(byte[] out, int outOff) {
		byte[] tmp = new byte[digestSize];
		digest.doFinal(tmp, 0);

		digest.update(outputPad, 0, outputPad.length);
		digest.update(tmp, 0, tmp.length);

		int len = digest.doFinal(out, outOff);

		reset();

		return len;
	}

	/**
	 * Reset the mac generator.
	 */
	public void reset() {
		/*
		 * reset the underlying digest.
		 */
		digest.reset();

		/*
		 * reinitialize the digest.
		 */
		digest.update(inputPad, 0, inputPad.length);
	}
}
