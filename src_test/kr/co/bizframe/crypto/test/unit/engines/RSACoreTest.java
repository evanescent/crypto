package kr.co.bizframe.crypto.test.unit.engines;

import java.math.BigInteger;
import java.security.SecureRandom;

import kr.co.bizframe.crypto.AsymmetricCipherKeyPair;
import kr.co.bizframe.crypto.ciphers.RSAEngine;
import kr.co.bizframe.crypto.generators.RSAKeyPairGenerator;
import kr.co.bizframe.crypto.params.RSAKeyGenerationParameters;
import kr.co.bizframe.crypto.params.RSAKeyParameters;
import kr.co.bizframe.crypto.util.ByteUtil;

public class RSACoreTest {

	public void test(){

		RSAEngine rsa = new RSAEngine();

		RSAKeyPairGenerator generator = new RSAKeyPairGenerator();

		BigInteger defaultPublicExponent = BigInteger.valueOf(0x10001);
	    int defaultTests = 12;
		SecureRandom sr = new SecureRandom();
		RSAKeyGenerationParameters param = new RSAKeyGenerationParameters(defaultPublicExponent,
				sr, 2048, defaultTests);
		generator.init(param);
		AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

		RSAKeyParameters publicKey = (RSAKeyParameters)keyPair.getPublic();
		System.out.println("publicKey modulus =" + publicKey.getModulus());
		System.out.println("publicKey modulus =" + publicKey.getModulus().bitLength());
		System.out.println("publicKey exp =" + publicKey.getExponent());

		RSAKeyParameters privateKey = (RSAKeyParameters)keyPair.getPrivate();
		System.out.println("privateKey modulus =" + privateKey.getModulus());
		System.out.println("privateKey exp =" + privateKey.getExponent());


		byte[] input = "abc".getBytes();
		rsa.init(true, keyPair.getPublic());
		byte[] output = rsa.processBlock(input, 0, input.length);
		System.out.println(" encrypted = " + ByteUtil.toHexString(output));


		rsa.init(false, keyPair.getPrivate());
		byte[] decrypted = rsa.processBlock(output, 0, output.length);
		System.out.println(" decrypted = " + ByteUtil.toHexString(decrypted));
		System.out.println(" decrypted = " + new String(decrypted));

	}


	public void test2() {

		String smsg = "11 22 33 44";
		smsg = ByteUtil.removeSpace(smsg);
		byte[] msg = ByteUtil.toByteArray(smsg);

		String pubExp = "01 00 01";
		pubExp = ByteUtil.removeSpace(pubExp);

		String priExp =
			"24 89 10 8B 0B 6A F8 6B ED 9E 44 C2 33 64 42 D5 E2 27 DB A5 5E F8 E2 6A 7E 43 71 94 11 90 77 F0 03 BC 9C 02 78 52 BB 31 26 C9 9C 16 D5 F1 05 7B C8 36 1D CB 26 A5 B2 DB 42 29 DB 3D E5 BD 97 9B 2E 59 7D 19 16 D7 BB C9 27 46 FC 07 59 5C 76 B4 4B 39 A4 76 A6 5C 86 F0 86 DC 92 83 CA 6D 1E EF C1 49 15 98 2F 9C 4C ED 5F 62 A9 FF 3B E2 42 18 A9 93 57 B5 B6 5C 3B 10 AE B3 67 E9 11 EB 9E 21";

		priExp = ByteUtil.removeSpace(priExp);

		String modulus =
			"F0 C4 2D B8 48 6F EB 95 95 D8 C7 8F 90 8D 04 A9 B6 C8 C7 7A 36 10 5B 1B F2 75 53 77 A6 89 3D C4 38 3C 54 EC 6B 52 62 E5 68 8E 5F 9D 9D D1 64 97 D0 E3 EA 83 3D EE 2C 8E BC D1 43 83 89 FC CA 8F ED E7 A8 8A 81 25 7E 8B 27 09 C4 94 D4 2F 72 3D EC 2E 0B 5C 09 73 1C 55 0D CC 9D 7E 75 25 89 89 1C BB C3 02 13 07 DD 91 8E 10 0B 34 C0 14 A5 59 E0 E1 82 AF B2 1A 72 B3 07 CC 39 5D EC 99 57 47";

		modulus = ByteUtil.removeSpace(modulus);

		RSAKeyParameters pubKey = new RSAKeyParameters(false, new BigInteger(modulus, 16), new BigInteger(pubExp, 16));
		RSAKeyParameters priKey = new RSAKeyParameters(true, new BigInteger(modulus, 16), new BigInteger(priExp, 16));

		RSAEngine rsa = new RSAEngine();
		rsa.init(true, pubKey);
		byte[] encrypted = rsa.processBlock(msg, 0, msg.length);

		System.out.println(" encrypted = " + ByteUtil.toHexString(encrypted));

	}



	public static void main(String[] argv) {

		RSACoreTest ct = new RSACoreTest();
		ct.test2();
	}
}
