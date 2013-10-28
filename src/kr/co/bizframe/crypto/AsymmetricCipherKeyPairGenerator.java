/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * interface that a public/private key pair generator should conform to.
 */
public interface AsymmetricCipherKeyPairGenerator {


	public void init(KeyGenerationParameters param);

	public AsymmetricCipherKeyPair generateKeyPair();
}
