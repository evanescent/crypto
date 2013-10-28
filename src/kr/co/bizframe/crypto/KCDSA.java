/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * KCDSA의 구현 인터페이스
 */
public interface KCDSA extends DSA {

	/**
	 * 처리 전 준비 시 호출한다.
	 */
	public void prepare();

	/**
	 * 사용할 해쉬 함수를 설정한다.
	 * 
	 * @param digest 사용할 해쉬 함수
	 */
	public void setDigest(ExtendedDigest digest);

}
