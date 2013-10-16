package kr.co.bizframe.crypto.test.unit.paddings;

import java.security.Key;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import kr.co.bizframe.crypto.ciphers.SEEDEngine;
import kr.co.bizframe.crypto.modes.CBCBlockCipher;
import kr.co.bizframe.crypto.paddings.PKCS7Padding;
import kr.co.bizframe.crypto.paddings.PaddedBufferedBlockCipher;
import kr.co.bizframe.crypto.params.KeyParameter;
import kr.co.bizframe.crypto.params.ParametersWithIV;
import kr.co.bizframe.crypto.util.ByteUtil;
import static org.junit.Assert.*;


public class SEEDPaddingTest {


	@Test
	private void testCBCPkcs7Padding(){

		SEEDEngine seed = new SEEDEngine();

		byte[] keyBytes = ByteUtil.toByteArray("2b7e151628aed2a6abf7158809cf4f3c");
		KeyParameter key = new KeyParameter(keyBytes);

 		byte[] fivBytes = ByteUtil.toByteArray("000102030405060708090A0B0C0D0E0F");
 		ParametersWithIV iv = new ParametersWithIV(key, fivBytes);

 		CBCBlockCipher bc = new CBCBlockCipher(seed);
 		PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(bc);
 		cipher.init(true, iv);

 		byte[] encrypted = new byte[seed.getBlockSize()];
		byte[] decrypted = new byte[seed.getBlockSize()];

		//byte[] plain = ByteUtil.toByteArray("000102030405060708090A0B0C0D0E0F");
		byte[] plain = ByteUtil.toByteArray("000102030405060708090A0B0C0D0E");


 		//bc.processBlock(plain, 0, encrypted, 0);
 		cipher.processBytes(plain, 0, 14, encrypted, 0);
 		//cipher.doFinal(out, outOff)
		System.out.println("encrypted =" + ByteUtil.toHexString(encrypted));

 		//bc.init(false, iv);
 		//bc.processBlock(encrypted, 0, decrypted, 0);

 		//System.out.println("decrypted =" + ByteUtil.toHexString(decrypted));

	}



	public static void main(String[] argv){

		try{
			SEEDPaddingTest st = new SEEDPaddingTest();
			st.testCBCPkcs7Padding();
		}catch(Exception e){
			e.printStackTrace();
		}
	}


}
