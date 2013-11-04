/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * 해쉬 함수가 구현할 기본 인터페이스
 */
public interface Digest {

	/**
	 * 알고리즘명을 반환한다.
	 *  
	 * @return 알고리즘명
	 */
	public String getAlgorithmName();

	/**
	 * 해쉬 결과 크기를 반환한다.
	 * 
	 * @return 해쉬 결과 크기
	 */
	public int getDigestSize();

	/**
	 * 주어진 바이트로 업데이트한다.
	 * 
	 * @param in 입력 바이트
	 */
	public void update(byte in);

	/**
	 * 주어진 바이트 배열로 업데이트한다.
	 * 
	 * @param in 입력 바이트 배열
	 * @param inOff 입력 바이트 위치
	 * @param len 입력 바이트 길이
	 */
	public void update(byte[] in, int inOff, int len);

	/**
	 * 주어진 바이트 배열에 결과를 출력한다.
	 * 
	 * @param out 출력 바이트 배열
	 * @param outOff 출력 바이트 위치
	 * @return 처리한 바이트 배열 크기
	 */
	public int doFinal(byte[] out, int outOff);

	/**
	 * 상태를 초기화 전으로 돌린다.
	 */
	public void reset();

}
