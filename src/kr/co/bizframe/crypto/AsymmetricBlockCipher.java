/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * 공개/비공개 키 블록 암호 암호 엔진이 구현해야 할 인터페이스
 */
public interface AsymmetricBlockCipher {

	/**
	 * 엔진 초기화 시에 호출한다.
	 *  
	 * @param forEncryption 암호화 여부, <code>true</code>면 암호화, 
	 *                      <code>false</code>면 복호화.
	 * @param params 처리에 필요한 키와 기타 초기화 매개변수
	 * @throws IllegalArgumentException 설정이 올바르지 않은 경우
	 */
	public void init(boolean forEncryption, CipherParameters param);

	/**
	 * 입력 블록 크기를 반환한다.
	 * 
	 * @return 입력 블록 크기
	 */
	public int getInputBlockSize();

	/**
	 * 출력 블록 크기를 반환한다.
	 * 
	 * @return 출력 블록 크기
	 */
	public int getOutputBlockSize();

	/**
	 * 매개변수를 받은 블록에 대한 처리를 진행한다.
	 * 
	 * @param in 입력 블록 바이트 배열
	 * @param inOff 입력 블록 바이트 위치
	 * @param len 입력 블록 바이트 크기
	 * @return 출력 블록 바이트 배열
	 * @throws InvalidCipherTextException 블록 암호화 처리 도중 오류가 발생한 경우
	 */
	public byte[] processBlock(byte[] in, int inOff, int len) 
			throws InvalidCipherTextException;

}
