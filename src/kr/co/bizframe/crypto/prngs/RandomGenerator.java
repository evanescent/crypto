/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.prngs;

/**
 * 난수생성기를 위한 인터페이스
 */
public interface RandomGenerator {

	/**
	 * Add more seed material to the generator.
	 *
	 * @param seed
	 *            a byte array to be mixed into the generator's state.
	 */
	public void addSeedMaterial(byte[] seed);

	/**
	 * Add more seed material to the generator.
	 *
	 * @param seed
	 *            a long value to be mixed into the generator's state.
	 */
	public void addSeedMaterial(long seed);

	/**
	 * 주어진 바이트 배열에 임의의 값을 채워넣는다.
	 *
	 * @param bytes 임의의 값을 채워넣고자 하는 바이트 배열 
	 */
	public void nextBytes(byte[] bytes);

	/**
	 * 주어진 바이트 배열의 지정한 위치에 임의의 값을 채워넣는다.
	 *
	 * @param bytes 임의의 값을 채워넣고자 하는 바이트 배열
	 * @param start 채워넣고자 하는 시작 위치
	 * @param len 채워넣고자 하는 길이
	 */
	public void nextBytes(byte[] bytes, int start, int len);

}
