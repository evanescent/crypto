/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

import java.util.HashMap;
import java.util.Map;

import kr.co.bizframe.crypto.ciphers.CipherManager;
import kr.co.bizframe.crypto.digests.DigestManager;

/**
 * 
 */
public class Algorithms {

	public static enum Type {
		BLOCK_CIPHER, MODE, MAC, DIGEST
	}

	private Map<String, Algorithm> algorithms = new HashMap<String, Algorithm>();

	public void addBlockCipher(String name, Class<? extends BlockCipher> clazz) {
		Algorithm algo = new BlockCipherAlgorithm(name, Type.BLOCK_CIPHER, clazz, null);
		algorithms.put(name, algo);
	}

	public void addBlockCipher(String name, Class<? extends BlockCipher> clazz, Class<? extends BlockCipher> mode) {

		BlockCipherAlgorithm algo = new BlockCipherAlgorithm(name, Type.BLOCK_CIPHER, clazz, mode);
		algorithms.put(name, algo);
	}

	public void addDigest(String name, Class<? extends Digest> clazz) {

		DigestAlgorithm algo = new DigestAlgorithm(name, Type.DIGEST, clazz);
		algorithms.put(name, algo);
	}

	public CipherManager getBlockCipher(String name) {

		BlockCipherAlgorithm algo = (BlockCipherAlgorithm) algorithms.get(name);
		if (algo == null) {
			throw new NullPointerException("algorithm is null");
		}

		Class<? extends BlockCipher> blockClass = algo.getBlockClass();
		Class<? extends BlockCipher> modeClass = algo.getModeClass();

		BlockCipher cipher = null;
		try {
			cipher = blockClass.newInstance();

			if (modeClass != null)
				cipher = modeClass.getConstructor(blockClass).newInstance(cipher);

		} catch (Exception e) {
			e.printStackTrace();
		}
		CipherManager manager = new CipherManager(cipher);
		return manager;
	}

	public DigestManager getDigest(String name) {

		DigestAlgorithm algo = (DigestAlgorithm) algorithms.get(name);
		if (algo == null) {
			throw new NullPointerException("algorithm=[" + name + "] is not supported.");
		}

		Class<? extends Digest> digestClass = algo.getDigestClass();
		Digest digest = null;
		try {
			digest = digestClass.newInstance();
		} catch (Exception e) {
			e.printStackTrace();
		}

		DigestManager manager = new DigestManager(digest);
		return manager;
	}

	private abstract class Algorithm {

		private String name;
		private Type type;

		public Algorithm(String name, Type type) {
			this.name = name;
			this.type = type;
		}

		public String getName() {
			return name;
		}

		public Type getType() {
			return type;
		}

	}

	private class BlockCipherAlgorithm extends Algorithm {

		private Class<? extends BlockCipher> blockClass;

		private Class<? extends BlockCipher> modeClass;

		public BlockCipherAlgorithm(String name, Type type, Class<? extends BlockCipher> clazz, Class<? extends BlockCipher> mode) {

			super(name, type);
			this.blockClass = clazz;
			this.modeClass = mode;
		}

		public Class<? extends BlockCipher> getBlockClass() {
			return blockClass;
		}

		public Class<? extends BlockCipher> getModeClass() {
			return modeClass;
		}

	}

	private class DigestAlgorithm extends Algorithm {

		private Class<? extends Digest> digestClass;

		public DigestAlgorithm(String name, Type type, Class<? extends Digest> clazz) {

			super(name, type);
			this.digestClass = clazz;
		}

		public Class<? extends Digest> getDigestClass() {
			return digestClass;
		}

	}
}
