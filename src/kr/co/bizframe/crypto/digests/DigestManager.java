/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.digests;

import kr.co.bizframe.crypto.Digest;


public class DigestManager {

	private Digest digest;

	/**
	 * Digest를 반환한다.
	 * @param digest Digest 구현 인터페이스
	 */
	public DigestManager(Digest digest){
		this.digest = digest;
	}

	/**
	 * Digest의 Size를 반환한다.
 	 * @return Digest size
	 */
	public int getDigestSize(){
		return digest.getDigestSize();
	}

	/**
	 * 암복호화 대상을  byte 형태로 Digest를 갱신한다.
	 * @param in 암복호화 대상인 byte 데이터
	 */
	public void update(byte in){
		digest.update(in);
	}

	
	/**
	 * 
	 * 암복호화 대상을  byte 형태로 지정된 inOff로부터 시작하여 Digest를 갱신한다.
	 * @param in 암복호화 대상인 byte 데이터
	 * @param inOff 시작 offset
	 * @param len 사용되는 바이트 수 
	 */
	public void update(byte[] in, int inOff, int len){
		digest.update(in, inOff, len);
	}

	//public int doFinal(byte[] out, int outOff){
	//	return digest.doFinal(out, outOff);
	//}

	/**
	 * 암복호화를 처리한뒤 결과를 반환한다.
	 * @return byte[] 암복호화된 데이터
	 */
	public byte[] digest(){
		byte[]  digestBytes = new byte[digest.getDigestSize()];
		digest.doFinal(digestBytes, 0);
		return digestBytes;
	}

	/**
	 * 재사용을 위해 Digest를 초기화 시킨다.
	 */
	public void reset(){
		digest.reset();
	}


}
