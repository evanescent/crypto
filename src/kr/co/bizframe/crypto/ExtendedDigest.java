/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * 해쉬 함수의 확장 인터페이스
 */
public interface ExtendedDigest extends Digest {

	/**
	 * 해쉬 함수의 내부 블록 버퍼 크기를 반환한다.
	 *
	 * @return 해쉬 함수의 내부 블록 버퍼 크기
	 */
	public int getByteLength();
	
}
