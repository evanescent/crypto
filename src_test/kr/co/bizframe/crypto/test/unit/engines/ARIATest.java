package kr.co.bizframe.crypto.test.unit.engines;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import kr.co.bizframe.crypto.ciphers.ARIAEngine;
import kr.co.bizframe.crypto.params.KeyParameter;
import kr.co.bizframe.crypto.util.ByteUtil;

public class ARIATest {


	public void test(){

		try{
			ARIAEngine aria = new ARIAEngine();

			// 128 key
			String skey = "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff";
			byte[] key = ByteUtil.toByteArray(true, skey);
			String splain = "11 11 11 11 aa aa aa aa 11 11 11 11 bb bb bb bb";
			byte[] plain = ByteUtil.toByteArray(true, splain);


			byte[] encrypted = new byte[aria.getBlockSize()];
			byte[] decrypted = new byte[aria.getBlockSize()];

			KeyParameter key128 = new KeyParameter(key);
			aria.init(true, key128);

			aria.processBlock(plain, 0, encrypted, 0);

			System.out.println(ByteUtil.toHexString(encrypted));

			// 192 key
			skey = "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"+
					"00 11 22 33 44 55 66 77";
			key = ByteUtil.toByteArray(true, skey);

			splain = "11 11 11 11 aa aa aa aa 11 11 11 11 bb bb bb bb";
			plain = ByteUtil.toByteArray(true, splain);

			KeyParameter key192 = new KeyParameter(key);
			aria.init(true, key192);

			aria.processBlock(plain, 0, encrypted, 0);
			System.out.println(ByteUtil.toHexString(encrypted));

			// 256 key
			skey = "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"+
					"00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff";
			key = ByteUtil.toByteArray(true, skey);

			splain = "11 11 11 11 aa aa aa aa 11 11 11 11 bb bb bb bb";
			plain = ByteUtil.toByteArray(true, splain);

			KeyParameter key256 = new KeyParameter(key);
			aria.init(true, key256);

			aria.processBlock(plain, 0, encrypted, 0);
			System.out.println(ByteUtil.toHexString(encrypted));

		}catch(Exception e){
			e.printStackTrace();
		}

	}

	public static void main(String[] args) {

		ARIATest st = new ARIATest();
		st.test();


	}



}
