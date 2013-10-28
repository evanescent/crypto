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
 * 지원하는 알고리즘을 담고 있는 클래스
 */
public class Algorithms {

	public static enum Type {
		/**
		 * 블록 암호 알고리즘
		 */
		BLOCK_CIPHER, 
		
		/**
		 * 운용 모드
		 */
		MODE, 
		
		/**
		 * 메시지 인증 코드
		 */
		MAC,
		
		/**
		 * 해쉬 함수
		 */
		DIGEST
	}

	private Map<String, Algorithm> algorithms = new HashMap<String, Algorithm>();

	/**
	 * 블록 암호 알고리즘을 추가한다.
	 * 
	 * @param name 블록 암호 알고리즘명
	 * @param clazz 블록 암호 알고리즘 구현 클래스
	 */
	public void addBlockCipher(String name, Class<? extends BlockCipher> clazz) {
		Algorithm algo = new BlockCipherAlgorithm(name, Type.BLOCK_CIPHER, clazz, null);
		algorithms.put(name, algo);
	}

	/**
	 * 블록 암호 알고리즘을 추가한다.
	 * 
	 * @param name 블록 암호 알고리즘명
	 * @param clazz 블록 암호 알고리즘 구현 클래스
	 * @param mode 운용 모드
	 */
	public void addBlockCipher(String name, Class<? extends BlockCipher> clazz, 
			Class<? extends BlockCipher> mode) {
		BlockCipherAlgorithm algo = new BlockCipherAlgorithm(name, Type.BLOCK_CIPHER, clazz, mode);
		algorithms.put(name, algo);
	}

	/**
	 * 해쉬 함수를 추가한다.
	 * 
	 * @param name 해쉬 함수명
	 * @param clazz 해쉬 함수 구현 클래스
	 */
	public void addDigest(String name, Class<? extends Digest> clazz) {
		DigestAlgorithm algo = new DigestAlgorithm(name, Type.DIGEST, clazz);
		algorithms.put(name, algo);
	}

	/**
	 * 주어진 알고리즘명에 해당하는 블록 암호 알고리즘 구현을 반환한다.
	 * 
	 * @param name 블록 암호 알고리즘명
	 * @return 해당하는 알고리즘에 대한 구현
	 * @throws NullPointerException 해당 알고리즘명이 등록되어 있지 않은 경우
	 * @throws IllegalStateException 해당 알고리즘에 대한 구현체를 생성할 수 없는 경우
	 */
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
			throw new IllegalStateException(e);
		}
		CipherManager manager = new CipherManager(cipher);
		return manager;
	}

	/**
	 * 주어진 알고리즘명에 해당하는 해쉬 함수 구현을 반환한다.
	 * 
	 * @param name 해쉬 함수 알고리즘명
	 * @return 해당하는 알고리즘에 대한 구현
	 * @throws NullPointerException 해당 알고리즘명이 등록되어 있지 않은 경우
	 * @throws IllegalStateException 해당 알고리즘에 대한 구현체를 생성할 수 없는 경우
	 */
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
			throw new IllegalStateException(e);
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

		public BlockCipherAlgorithm(String name, Type type, 
				Class<? extends BlockCipher> clazz, Class<? extends BlockCipher> mode) {
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
