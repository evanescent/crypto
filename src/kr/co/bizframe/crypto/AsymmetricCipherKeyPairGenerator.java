package kr.co.bizframe.crypto;

/**
 * interface that a public/private key pair generator should conform to.
 */
public interface AsymmetricCipherKeyPairGenerator {


	public void init(KeyGenerationParameters param);

	public AsymmetricCipherKeyPair generateKeyPair();
}
