/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * 메시지 인증 코드(MACs)가 구현할 기본 인터페이스
 */
public interface Mac {

	/**
	 * 메시지 인증 코드 초기화 시에 호출한다.
	 * 
	 * @param params 처리에 필요한 키와 기타 초기화 매개변수
	 * @throws IllegalArgumentException 설정이 올바르지 않은 경우
	 */
	public void init(CipherParameters params) throws IllegalArgumentException;

	/**
	 * 알고리즘명을 반환한다.
	 *  
	 * @return 알고리즘명
	 */
	public String getAlgorithmName();

	/**
	 * 메시지 인증 코드 결과 크기를 반환한다.
	 * 
	 * @return 메시지 인증 코드 결과 크기
	 */
	public int getMacSize();

	/**
	 * 주어진 바이트로 업데이트한다.
	 * 
	 * @param in 입력 바이트
	 * @throws IllegalStateException 처리 상태가 올바르지 않은 경우
	 */
	public void update(byte in) throws IllegalStateException;

	/**
	 * 주어진 바이트 배열로 업데이트한다.
	 * 
	 * @param in 입력 바이트 배열
	 * @param inOff 입력 바이트 위치
	 * @param len 입력 바이트 길이
	 * @throws DataLengthException 블록 길이가 올바르지 않은 경우
	 * @throws IllegalStateException 처리 상태가 올바르지 않은 경우
	 */
	public void update(byte[] in, int inOff, int len)
			throws DataLengthException, IllegalStateException;

	/**
	 * 주어진 바이트 배열에 결과를 출력한다.
	 * 
	 * @param out 출력 바이트 배열
	 * @param outOff 출력 바이트 위치
	 * @return 처리한 바이트 배열 크기
	 * @throws DataLengthException 블록 길이가 올바르지 않은 경우
	 * @throws IllegalStateException 처리 상태가 올바르지 않은 경우
	 */
	public int doFinal(byte[] out, int outOff) throws DataLengthException,
			IllegalStateException;

	/**
	 * 상태를 초기화 전으로 돌린다.
	 */
	public void reset();
	
}
