package kr.co.bizframe.crypto;

/**
 * a holding class for public/private parameter pairs.
 */
public class AsymmetricCipherKeyPair {

	private CipherParameters publicParam;
	private CipherParameters privateParam;


	public AsymmetricCipherKeyPair(CipherParameters publicParam,
			CipherParameters privateParam) {
		this.publicParam = publicParam;
		this.privateParam = privateParam;
	}

	public CipherParameters getPublic() {
		return publicParam;
	}


	public CipherParameters getPrivate() {
		return privateParam;
	}
}
