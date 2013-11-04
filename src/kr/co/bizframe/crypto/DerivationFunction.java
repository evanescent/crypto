/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * 일반적인 목적의 바이트 배열 유도함수(Derivation Function; DF)를 위한 인터페이스
 */
public interface DerivationFunction {
	
	/**
	 * 주어진 매개변수를 사용해 초기화한다.
	 * 
	 * @param param 초기화에 사용할 매개변수
	 */
	public void init(DerivationParameters param);

	/**
	 * 유도함수가 사용할 해쉬함수를 반환한다.
	 */
	public Digest getDigest();

	/**
	 * 바이트 배열을 유도해 반환한다.
	 *  
	 * @param out 출력 바이트 배열
	 * @param outOff 출력 블록 바이트 위치
	 * @param len 유도할 바이트 길이
	 * @return 생성한 바이트 배열의 길이
	 * @throws DataLengthException 블록 길이가 올바르지 않은 경우
	 * @throws IllegalStateException 처리 상태가 올바르지 않은 경우
	 */
	public int generateBytes(byte[] out, int outOff, int len) 
			throws DataLengthException, IllegalArgumentException;

}
