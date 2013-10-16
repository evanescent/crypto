package kr.co.bizframe.crypto.test.unit.engines;

import org.junit.Test;

import kr.co.bizframe.crypto.ciphers.SEEDEngine;
import kr.co.bizframe.crypto.params.KeyParameter;
import kr.co.bizframe.crypto.util.ByteUtil;
import static org.junit.Assert.*;


public class SEEDTest {

	SEEDEngine seed = new SEEDEngine();


	@Test
	public void test1() throws Exception {

		SEEDEngine seed = new SEEDEngine();

		byte[] encrypted = new byte[seed.getBlockSize()];
		byte[] decrypted = new byte[seed.getBlockSize()];

		byte[] bKeys = ByteUtil.toByteArray("00000000000000000000000000000000");
		byte[] plain = ByteUtil.toByteArray("000102030405060708090A0B0C0D0E0F");
		byte[] answer = ByteUtil.toByteArray("5ebac6e0054e166819aff1cc6d346cdb");

		KeyParameter key = new KeyParameter(bKeys);
		seed.init(true, key);

		seed.processBlock(plain, 0, encrypted, 0);

		System.out.println("encrypted =" + ByteUtil.toHexString(encrypted));
		assertEquals(ByteUtil.toHexString(encrypted), ByteUtil.toHexString(answer));


		seed.init(false, key);
		seed.processBlock(encrypted, 0, decrypted, 0);

		System.out.println("decrypted =" +ByteUtil.toHexString(decrypted));
		assertEquals(ByteUtil.toHexString(decrypted), ByteUtil.toHexString(plain));
	}



	public static void main(String[] argv){

		try{
			SEEDTest st = new SEEDTest();
			st.test1();
		}catch(Exception e){
			e.printStackTrace();
		}
	}


}
