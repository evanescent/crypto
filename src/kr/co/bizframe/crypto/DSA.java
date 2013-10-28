/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

import java.math.BigInteger;

/**
 * 전자서명 알고리즘(Digital Signature Algorithm)이 구현해야 할 인터페이스.
 */
public interface DSA {

	/**
	 * 전자서명 생성 또는 검증 시에 호출할 초기화 함수
	 *
	 * @param forSigning 전자서명 생성 여부, <code>true</code>면 생성, 
	 *                   <code>false</code>면 검증.
	 * @param params 처리에 필요한 키와 기타 초기화 매개변수
	 */
	public void init(boolean forSigning, CipherParameters param);

	/**
	 * 주어진 바이트 배열에 대해 전자서명을 생성한다.
	 *
	 * @param message 서명할 메시지 바이트 배열
	 * @return r과 s로 표현되는 2개의 큰 정수값
	 */
	public BigInteger[] generateSignature(byte[] message);

	/**
	 * 서명값 r과 s에 대해 주어진 메시지에 대한 검증을 시도한다.
	 *
	 * @param message 서명에 사용한 메시지
	 * @param r 서명값 r
	 * @param s 서명값 s
	 */
	public boolean verifySignature(byte[] message, BigInteger r, BigInteger s);
}
