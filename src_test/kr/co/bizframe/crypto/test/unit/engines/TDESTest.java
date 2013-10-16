package kr.co.bizframe.crypto.test.unit.engines;

import kr.co.bizframe.crypto.ciphers.DESedeEngine;
import kr.co.bizframe.crypto.ciphers.SEEDEngine;
import kr.co.bizframe.crypto.params.KeyParameter;
import kr.co.bizframe.crypto.util.ByteUtil;

public class TDESTest {




	public void test() throws Exception {

		DESedeEngine tdes = new DESedeEngine();

		byte[] encrypted = new byte[tdes.getBlockSize()];
		byte[] decrypted = new byte[tdes.getBlockSize()];

		byte[] bKeys = ByteUtil.toByteArray("800000000000000000000000000000000000000000000000");
		byte[] p = ByteUtil.toByteArray("0000000000000000");

		KeyParameter key = new KeyParameter(bKeys);
		tdes.init(true, key);

		tdes.processBlock(p, 0, encrypted, 0);

		System.out.println("encrypted =" + ByteUtil.toHexString(encrypted));

		tdes.init(false, key);
		tdes.processBlock(encrypted, 0, decrypted, 0);

		System.out.println("decrypted =" +ByteUtil.toHexString(decrypted));
	}



	public static void main(String[] argv){

		try{
			TDESTest st = new TDESTest();
			st.test();
		}catch(Exception e){
			e.printStackTrace();
		}
	}
}
