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
	 * Digest�� ��ȯ�Ѵ�.
	 * @param digest Digest ���� �������̽�
	 */
	public DigestManager(Digest digest){
		this.digest = digest;
	}

	/**
	 * Digest�� Size�� ��ȯ�Ѵ�.
 	 * @return Digest size
	 */
	public int getDigestSize(){
		return digest.getDigestSize();
	}

	/**
	 * �Ϻ�ȣȭ �����  byte ���·� Digest�� �����Ѵ�.
	 * @param in �Ϻ�ȣȭ ����� byte ������
	 */
	public void update(byte in){
		digest.update(in);
	}

	
	/**
	 * 
	 * �Ϻ�ȣȭ �����  byte ���·� ������ inOff�κ��� �����Ͽ� Digest�� �����Ѵ�.
	 * @param in �Ϻ�ȣȭ ����� byte ������
	 * @param inOff ���� offset
	 * @param len ���Ǵ� ����Ʈ �� 
	 */
	public void update(byte[] in, int inOff, int len){
		digest.update(in, inOff, len);
	}

	//public int doFinal(byte[] out, int outOff){
	//	return digest.doFinal(out, outOff);
	//}

	/**
	 * �Ϻ�ȣȭ�� ó���ѵ� ����� ��ȯ�Ѵ�.
	 * @return byte[] �Ϻ�ȣȭ�� ������
	 */
	public byte[] digest(){
		byte[]  digestBytes = new byte[digest.getDigestSize()];
		digest.doFinal(digestBytes, 0);
		return digestBytes;
	}

	/**
	 * ������ ���� Digest�� �ʱ�ȭ ��Ų��.
	 */
	public void reset(){
		digest.reset();
	}


}
