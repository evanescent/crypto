package kr.co.bizframe.crypto;



public interface KCDSA extends DSA {

	public void prepare();

	public void setDigest(ExtendedDigest digest);

}
