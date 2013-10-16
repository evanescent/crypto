package kr.co.bizframe.crypto.test.unit.signer;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.SignatureException;

import kr.co.bizframe.crypto.AsymmetricCipherKeyPair;
import kr.co.bizframe.crypto.digests.GeneralDigest;
import kr.co.bizframe.crypto.digests.HAS160Digest;
import kr.co.bizframe.crypto.generators.KCDSAKeyPairGenerator;
import kr.co.bizframe.crypto.generators.KCDSAParametersGenerator;
import kr.co.bizframe.crypto.params.KCDSAKeyGenerationParameters;
import kr.co.bizframe.crypto.params.KCDSAParameters;
import kr.co.bizframe.crypto.signers.KCDSASigner;
import kr.co.bizframe.crypto.util.ByteUtil;

import org.apache.log4j.BasicConfigurator;


public class KCDSASignerTest {

	static {
		BasicConfigurator.configure();
	}

	public static void main(String[] args) throws SignatureException {
		System.setProperty("bfsec.test.vector", "true");
		System.setProperty("bfsec.debug", "true");

		String message = "This is a test message for KCDSA usage!";

		System.out.println( "Message: " + ByteUtil.toHexString(message.getBytes()) );

		KCDSAParametersGenerator gen = new KCDSAParametersGenerator();
		SecureRandom random = new SecureRandom();
		gen.init(1024, 160, 40, random);
		KCDSAParameters params = gen.generateParameters();
		KCDSAKeyGenerationParameters keyGenParam = new KCDSAKeyGenerationParameters(random, params);
		KCDSAKeyPairGenerator pairGen = new KCDSAKeyPairGenerator();
		pairGen.init(keyGenParam);
		AsymmetricCipherKeyPair keyPair = pairGen.generateKeyPair();

		KCDSASigner signer = new KCDSASigner();
		HAS160Digest digest = new HAS160Digest();
		signer.setDigest(digest);

		signer.init(true, keyPair.getPrivate());
		digest.update(message.getBytes(), 0, message.getBytes().length);
		byte[] hash = new byte[digest.getDigestSize()];
		digest.doFinal(hash, 0);
		BigInteger[] sig = signer.generateSignature(hash);

		signer.init(false, keyPair.getPublic());
		digest.update(message.getBytes(), 0, message.getBytes().length);
		digest.doFinal(hash, 0);
		if( signer.verifySignature(hash, sig[0], sig[1]) ) {
			System.out.println("verified");
		} else {
			System.out.println("not verified");
		}
	}


}
