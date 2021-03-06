package kr.co.bizframe.crypto.test.unit.modes;

import java.security.Key;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import kr.co.bizframe.crypto.ciphers.SEEDEngine;
import kr.co.bizframe.crypto.modes.CBCBlockCipher;
import kr.co.bizframe.crypto.params.KeyParameter;
import kr.co.bizframe.crypto.params.ParametersWithIV;
import kr.co.bizframe.crypto.util.ByteUtil;
import static org.junit.Assert.*;


public class SEEDModesTest {


	@Test
	private void testCBC(){

		SEEDEngine seed = new SEEDEngine();
		System.out.println("test CBC");
		byte[] keyBytes = ByteUtil.toByteArray("2b7e151628aed2a6abf7158809cf4f3c");
		KeyParameter key = new KeyParameter(keyBytes);

 		byte[] fivBytes = ByteUtil.toByteArray("000102030405060708090A0B0C0D0E0F");
 		ParametersWithIV iv = new ParametersWithIV(key, fivBytes);

 		CBCBlockCipher bc = new CBCBlockCipher(seed);
 		bc.init(true, iv);

 		byte[] encrypted = new byte[seed.getBlockSize()];
		byte[] decrypted = new byte[seed.getBlockSize()];

		byte[] plain = ByteUtil.toByteArray("000102030405060708090A0B0C0D0E0F");

 		bc.processBlock(plain, 0, encrypted, 0);
 		System.out.println("encrypted =" + ByteUtil.toHexString(encrypted));

 		bc.init(false, iv);
 		bc.processBlock(encrypted, 0, decrypted, 0);

 		System.out.println("decrypted =" + ByteUtil.toHexString(decrypted));

	}



	public static void main(String[] argv){

		try{
			SEEDModesTest st = new SEEDModesTest();
			st.testCBC();
		}catch(Exception e){
			e.printStackTrace();
		}
	}


}
