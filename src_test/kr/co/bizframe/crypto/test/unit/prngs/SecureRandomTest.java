package kr.co.bizframe.crypto.test.unit.prngs;

import kr.co.bizframe.crypto.util.ByteUtil;

public class SecureRandomTest {


	public void test(){

		byte[] random = new byte[10];
		SecureRandom sr = new SecureRandom();
		sr.engineNextBytes(random);
		System.out.println(" random = " + ByteUtil.toHexString(random));

		sr.engineNextBytes(random);
		System.out.println(" random = " + ByteUtil.toHexString(random));


		String seed = "010001";
		sr.engineSetSeed(ByteUtil.toByteArray(seed));
		sr.engineNextBytes(random);
		System.out.println(" random = " + ByteUtil.toHexString(random));

		sr.engineNextBytes(random);
		System.out.println(" random = " + ByteUtil.toHexString(random));

	}

	public void test2(){

		byte[] random = new byte[10];
		java.security.SecureRandom sr = new java.security.SecureRandom();

		sr.nextBytes(random);

		System.out.println(" random = " + ByteUtil.toHexString(random));
	}



	public static void main(String[] argv){

		SecureRandomTest srt = new SecureRandomTest();
		srt.test();
	}
}
