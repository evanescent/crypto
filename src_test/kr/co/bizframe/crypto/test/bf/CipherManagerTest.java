package kr.co.bizframe.crypto.test.bf;

import kr.co.bizframe.crypto.BizframeCrypto;
import kr.co.bizframe.crypto.ciphers.CipherManager;
import kr.co.bizframe.crypto.util.ByteUtil;

public class CipherManagerTest {


	public void test(){

		try{
			BizframeCrypto bc = new BizframeCrypto();
			CipherManager cm = bc.getBlockCipher("ARIA");

			byte[] keyBytes = ByteUtil.toByteArray("00000000000000000000000000000000");
			byte[] ivBytes = ByteUtil.toByteArray("000102030405060708090A0B0C0D0E0F");

			//cm.init(true, ivBytes, keyBytes);
			cm.init(true, keyBytes);

			byte[] plain = ByteUtil.toByteArray("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E");
			byte[] ss = cm.doFinal(plain, 0, plain.length);

			System.out.println("ss = "+ ByteUtil.toHexString(ss));

		}catch(Exception e){
			e.printStackTrace();
		}
	}



	public void test2(){

		try{
			BizframeCrypto bc = new BizframeCrypto();
			CipherManager cm = bc.getBlockCipher("ARIA");

			byte[] keyBytes = ByteUtil.toByteArray("00000000000000000000000000000000");
			byte[] ivBytes = ByteUtil.toByteArray("000102030405060708090A0B0C0D0E0F");

			//cm.init(true, ivBytes, keyBytes);
			cm.init(true, keyBytes);

			byte[] plain = ByteUtil.toByteArray("000101");
			byte[] ss = cm.doFinal(plain, 0, plain.length);

			System.out.println("ss = "+ ByteUtil.toHexString(ss));

			cm.init(false, keyBytes);
			byte[] ss2 = cm.doFinal(ss, 0, ss.length);

			System.out.println("ss2 = "+ ByteUtil.toHexString(ss2));


		}catch(Exception e){
			e.printStackTrace();
		}
	}



	public static void main(String[] argv){

		CipherManagerTest bct = new CipherManagerTest();
		bct.test2();
	}
}
