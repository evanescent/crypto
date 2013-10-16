package kr.co.bizframe.crypto.test.unit.paddings;

import kr.co.bizframe.crypto.paddings.PKCS7Padding;
import kr.co.bizframe.crypto.util.ByteUtil;


public class PKCS7PaddingTest {


	public void test(){

		try{
			PKCS7Padding zp = new PKCS7Padding();
			//byte[] p = ByteUtil.toByteArray("6bc1bee22e409f96e93d7e117393172a");
			byte[] p = ByteUtil.toByteArray("6bc1be00");
			int n = zp.addPadding(p, 3);
			System.out.println("n =" + n);
			System.out.println("zp = " + ByteUtil.toHexString(p));

			int pc = zp.padCount(p);
			System.out.println("pc =" + n);

		}catch(Exception e){
			e.printStackTrace();
		}

	}

	public  static void main(String[] argv){

		PKCS7PaddingTest ppt = new PKCS7PaddingTest();
		ppt.test();

	}

}
