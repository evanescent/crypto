/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * 공개/비공개 키 쌍 생성기의 인터페이스
 */
public interface AsymmetricCipherKeyPairGenerator {

	/**
	 * 주어진 키 생성기의 매개변수로 초기화한다.
	 *  
	 * @param param 키 생성기의 초기화 매개변수
	 */
	public void init(KeyGenerationParameters param);

	/**
	 * 공개/비공개 키 쌍을 생성, 반환한다.
	 *  
	 * @return 생성한 공개/비공개 키 쌍 
	 */
	public AsymmetricCipherKeyPair generateKeyPair();
	
}
