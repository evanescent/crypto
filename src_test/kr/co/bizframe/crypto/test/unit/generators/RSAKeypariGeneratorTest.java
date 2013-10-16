package kr.co.bizframe.crypto.test.unit.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import kr.co.bizframe.crypto.AsymmetricCipherKeyPair;
import kr.co.bizframe.crypto.generators.RSAKeyPairGenerator;
import kr.co.bizframe.crypto.params.RSAKeyGenerationParameters;
import kr.co.bizframe.crypto.params.RSAKeyParameters;
import kr.co.bizframe.crypto.params.RSAPrivateCrtKeyParameters;

public class RSAKeypariGeneratorTest {



	public void test(){

		RSAKeyPairGenerator gen = new RSAKeyPairGenerator();

		RSAKeyGenerationParameters param = new RSAKeyGenerationParameters(
				BigInteger.valueOf(11L), new SecureRandom(), 16, 10);

		//gen.init(param);
		gen.init(param);
		AsymmetricCipherKeyPair kp = gen.generateKeyPair();
		RSAKeyParameters pub = (RSAKeyParameters)kp.getPublic();
		RSAPrivateCrtKeyParameters pri = (RSAPrivateCrtKeyParameters)kp.getPrivate();

		BigInteger exp  = pub.getExponent();
		BigInteger mod = pub.getModulus();

		System.out.println("exponent = " + exp);
		System.out.println("mod = " + mod);

	}

	public static void main(String[] argv){

		RSAKeypariGeneratorTest rp = new RSAKeypariGeneratorTest();
		rp.test();
	}


}
