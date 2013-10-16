package kr.co.bizframe.crypto.test.unit.paddings;

import kr.co.bizframe.crypto.paddings.ZeroBytePadding;
import kr.co.bizframe.crypto.util.ByteUtil;

public class ZeroPaddingTest {

	public void test(){

		try{
			ZeroBytePadding zp = new ZeroBytePadding();
			//byte[] p = ByteUtil.toByteArray("6bc1bee22e409f96e93d7e117393172a");
			byte[] p = ByteUtil.toByteArray("6bc1be");
			int n = zp.addPadding(p, 1);
			System.out.println("n =" + n);
			System.out.println("zp = " + ByteUtil.toHexString(p));

			int pc = zp.padCount(p);
			System.out.println("pc =" + n);

		}catch(Exception e){
			e.printStackTrace();
		}

	}


	public  static void main(String[] argv){

		ZeroPaddingTest zpt = new ZeroPaddingTest();
		zpt.test();
	}
}
