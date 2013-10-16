package kr.co.bizframe.crypto;

/**
 * base interface that a public/private key block cipher needs to conform to.
 */
public interface AsymmetricBlockCipher {

	public void init(boolean forEncryption, CipherParameters param);

	public int getInputBlockSize();

	public int getOutputBlockSize();

	public byte[] processBlock(byte[] in, int inOff, int len)
			throws InvalidCipherTextException;

}
