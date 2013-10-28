/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * 블록 암호 엔진이 구현해야 할 인터페이스
 */
public interface BlockCipher {

	/**
	 * 엔진 초기화 시에 호출한다.
	 *  
	 * @param forEncryption 암호화 여부, <code>true</code>면 암호화, 
	 *                      <code>false</code>면 복호화.
	 * @param params 처리에 필요한 키와 기타 초기화 매개변수
	 * @throws IllegalArgumentException 설정이 올바르지 않은 경우
	 */
	public void init(boolean forEncryption, CipherParameters params)
			throws IllegalArgumentException;

	/**
	 * 알고리즘명을 반환한다.
	 * 
	 * @return 알고리즘명
	 */
	public String getAlgorithmName();

	/**
	 * 블록 크기를 반환한다.
	 * 
	 * @return 블록 크기
	 */
	public int getBlockSize();

	/**
	 * 매개변수를 받은 블록에 대한 처리를 진행한다.
	 * 
	 * @param in 입력 블록 바이트 배열
	 * @param inOff 입력 블록 바이트 위치
	 * @param out 출력 블록 바이트 배열
	 * @param outOff 출력 블록 바이트 위치
	 * @return 처리한 블록 바이트 크기
	 * @throws DataLengthException 블록 길이가 올바르지 않은 경우
	 * @throws IllegalStateException 처리 상태가 올바르지 않은 경우
	 */
	public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
			throws DataLengthException, IllegalStateException;

	/**
	 * 상태를 초기화 전으로 돌린다.
	 */
	public void reset();

}
