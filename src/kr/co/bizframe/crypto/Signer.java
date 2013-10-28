/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * 일반적인 전자서명기가 구현할 인터페이스
 */
public interface Signer {

	/**
	 * 초기화 시에 호출한다.
	 *  
	 * @param forSigning 서명 여부, <code>true</code>면 서명, 
	 *                   <code>false</code>면 검증.
	 * @param param 처리에 필요한 키와 기타 초기화 매개변수
	 */
	public void init(boolean forSigning, CipherParameters param);

	/**
	 * 주어진 바이트로 업데이트한다.
	 * 
	 * @param b 입력 바이트
	 */
	public void update(byte b);

	/**
	 * 주어진 바이트 배열로 업데이트한다.
	 * 
	 * @param in 입력 바이트 배열
	 * @param off 입력 바이트 위치
	 * @param len 입력 바이트 길이
	 */
	public void update(byte[] in, int off, int len);

	/**
	 * 전자서명을 생성한다.
	 * 
	 * @return 생성된 전자서명 바이트 배열
	 * @throws CryptoException 서명 도중 오류가 발생한 경우 
	 * @throws DataLengthException 데이터 길이가 충분치 않은 경우
	 */
	public byte[] generateSignature() throws CryptoException,
			DataLengthException;

	/**
	 * 주어진 전자서명을 검증한다.
	 * 
	 * @return 검증 결과가 올바르다면 <code>true</code>, 아니라면 <code>false</code>
	 */
	public boolean verifySignature(byte[] signature);

	/**
	 * 최초 상태로 되돌린다.
	 */
	public void reset();
	
}
