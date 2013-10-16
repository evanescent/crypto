package kr.co.bizframe.crypto.test.unit.macs;

import kr.co.bizframe.crypto.digests.SHA1Digest;
import kr.co.bizframe.crypto.macs.HMac;
import kr.co.bizframe.crypto.params.KeyParameter;
import kr.co.bizframe.crypto.util.ByteUtil;

public class HMacTest {




	public void test(){

		SHA1Digest digest = new SHA1Digest();
		HMac mac = new HMac(digest);


		//String keys = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
		//				 "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

		String keys = "303132333435363738393a3b3c3d3e3f40414243";


		byte[] keyBytes = ByteUtil.toByteArray(keys);
		KeyParameter key = new KeyParameter(keyBytes);

		//String text = "Sample #1";
		String text = "Sample #2";
		byte[] out = new byte[20];
		mac.init(key);
		mac.update(text.getBytes(), 0, text.getBytes().length);
		mac.doFinal(out, 0);

		System.out.println("mac = " + ByteUtil.toHexString(out));


	}

	public static void main(String[] argv){

		HMacTest hmtest = new HMacTest();
		hmtest.test();

	}
}
