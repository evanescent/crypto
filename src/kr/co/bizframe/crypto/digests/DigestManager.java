package kr.co.bizframe.crypto.digests;

import kr.co.bizframe.crypto.Digest;

public class DigestManager {

	private Digest digest;

	public DigestManager(Digest digest){
		this.digest = digest;
	}

	public int getDigestSize(){
		return digest.getDigestSize();
	}

	public void update(byte in){
		digest.update(in);
	}

	public void update(byte[] in, int inOff, int len){
		digest.update(in, inOff, len);
	}

	//public int doFinal(byte[] out, int outOff){
	//	return digest.doFinal(out, outOff);
	//}

	public byte[] digest(){
		byte[]  digestBytes = new byte[digest.getDigestSize()];
		digest.doFinal(digestBytes, 0);
		return digestBytes;
	}

	public void reset(){
		digest.reset();
	}


}
