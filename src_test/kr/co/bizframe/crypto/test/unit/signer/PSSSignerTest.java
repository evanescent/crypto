package kr.co.bizframe.crypto.test.unit.signer;

import java.math.BigInteger;
import java.security.SecureRandom;

import kr.co.bizframe.crypto.AsymmetricCipherKeyPair;
import kr.co.bizframe.crypto.ciphers.RSAEngine;
import kr.co.bizframe.crypto.digests.SHA1Digest;
import kr.co.bizframe.crypto.generators.RSAKeyPairGenerator;
import kr.co.bizframe.crypto.params.RSAKeyGenerationParameters;
import kr.co.bizframe.crypto.params.RSAKeyParameters;
import kr.co.bizframe.crypto.signers.PSSSigner;
import kr.co.bizframe.crypto.util.ByteUtil;

public class PSSSignerTest {


	public void test(){

		try{
			RSAEngine rsa = new RSAEngine();
			PSSSigner signer = new PSSSigner(rsa, new SHA1Digest(), new SHA1Digest(), 4);

			RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
			BigInteger defaultPublicExponent = BigInteger.valueOf(0x10001);
		    int defaultTests = 12;
			SecureRandom sr = new SecureRandom();
			RSAKeyGenerationParameters param = new RSAKeyGenerationParameters(defaultPublicExponent,
					sr, 2048, defaultTests);
			generator.init(param);
			AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

			signer.init(true, keyPair.getPrivate());
			byte[] source = "sss".getBytes();
			signer.update(source, 0, source.length);
			byte[] sign = signer.generateSignature();

			signer.init(false, keyPair.getPublic());
			signer.update(source, 0, source.length);
			boolean vs = signer.verifySignature(sign);
			System.out.println("signer verify = "+ vs);

		}catch(Exception e){
			e.printStackTrace();
		}

	}



	public void test2(){

		try{
			RSAEngine rsa = new RSAEngine();
			PSSSigner signer = new PSSSigner(rsa, new SHA1Digest(), 20);

			String modulus = "a56e4a0e701017589a5187dc7ea841d1" +
								   "56f2ec0e36ad52a44dfeb1e61f7ad991" +
								   "d8c51056ffedb162b4c0f283a12a88a3" +
								   "94dff526ab7291cbb307ceabfce0b1df"+
								   "d5cd9508096d5b2b8b6df5d671ef6377"+
								   "c0921cb23c270a70e2598e6ff89d19f1"+
								   "05acc2d3f0cb35f29280e1386b6f64c4"+
								   "ef22e1e1f20d0ce8cffb2249bd9a2137";

			//byte[] modulus =  ByteUtil.toByteArray(smodulus);

			String pexponent = "010001";
			//byte[] pexponent  = ByteUtil.toByteArray(spexponent);

			String dexponent = "33a5042a90b27d4f5451ca9bbbd0b447"+
				                      "71a101af884340aef9885f2a4bbe92e8"+
				                      "94a724ac3c568c8f97853ad07c0266c8"+
				                      "c6a3ca0929f1e8f11231884429fc4d9a"+
				                      "e55fee896a10ce707c3ed7e734e44727"+
				                      "a39574501a532683109c2abacaba283c" +
				                      "31b4bd2f53c3ee37e352cee34f9e503b"+
				                      "d80c0622ad79c6dcee883547c6a3b325";

			//byte[] dexponent  = ByteUtil.toByteArray(sdexponent);

			RSAKeyParameters pubKey = new RSAKeyParameters(false, new BigInteger(modulus, 16), new BigInteger(pexponent, 16));
			RSAKeyParameters priKey = new RSAKeyParameters(true, new BigInteger(modulus, 16), new BigInteger(dexponent, 16));


			//System.out.println("xxx = " +ByteUtil.toHexString( new BigInteger(modulus, 16)));
			System.out.println("xxxxx"  + new BigInteger(modulus, 16).bitLength());
			//System.out.println("xxxxx"  + new BigInteger(dexponent).bitLength());
			//System.out.println("xxxxx"  + new BigInteger(pexponent).bitLength());

			signer.init(true, priKey);

			String msg = "cd c8 7d a2 23 d7 86 df 3b 45 e0 bb bc 72 13 26"+
			"d1 ee 2a f8 06 cc 31 54 75 cc 6f 0d 9c 66 e1 b6"+
			"23 71 d4 5c e2 39 2e 1a c9 28 44 c3 10 10 2f 15"+
			"6a 0d 8d 52 c1 f4 c4 0b a3 aa 65 09 57 86 cb 76"+
			"97 57 a6 56 3b a9 58 fe d0 bc c9 84 e8 b5 17 a3"+
			"d5 f5 15 b2 3b 8a 41 e7 4a a8 67 69 3f 90 df b0"+
			"61 a6 e8 6d fa ae e6 44 72 c0 0e 5f 20 94 57 29"+
			"cb eb e7 7f 06 ce 78 e0 8f 40 98 fb a4 1f 9d 61"+
			"93 c0 31 7e 8b 60 d4 b6 08 4a cb 42 d2 9e 38 08"+
			"a3 bc 37 2d 85 e3 31 17 0f cb f7 cc 72 d0 b7 1c"+
			"29 66 48 b3 a4 d1 0f 41 62 95 d0 80 7a a6 25 ca"+
			"b2 74 4f d9 ea 8f d2 23 c4 25 37 02 98 28 bd 16"+
			"be 02 54 6f 13 0f d2 e3 3b 93 6d 26 76 e0 8a ed"+
			"1b 73 31 8b 75 0a 01 67 d0";

			byte[] source = ByteUtil.toByteArray(true, msg);
			System.out.println("source length  =" + source.length);

			signer.update(source, 0, source.length);
			byte[] sign = signer.generateSignature();
			System.out.println("sign = "+ ByteUtil.toHexString(sign));


			//signer.init(false, keyPair.getPublic());
			//signer.update(source, 0, source.length);
			//boolean vs = signer.verifySignature(sign);
			//System.out.println("signer verify = "+ vs);

		}catch(Exception e){
			e.printStackTrace();
		}
	}


	public void test3(){

		BigInteger big = BigInteger.valueOf(9202000L);
		System.out.println("xxxxx"  + ByteUtil.toHexString(big));

		String ss =  "8c6950";


		BigInteger bi = new BigInteger(ByteUtil.toByteArray(true, ss));

		System.out.println("bi = "+ bi);
		System.out.println("xxxxx"  + ByteUtil.toHexString(bi));


		BigInteger bi2 = new BigInteger(ss, 16);
		System.out.println("bi2 = "+ bi2);
	}


	public static void main(String[] argv){
		PSSSignerTest pt = new PSSSignerTest();
		pt.test2();

	}
}
