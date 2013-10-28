/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * the foundation class for the exceptions thrown by the crypto packages.
 */
public class RuntimeCryptoException extends RuntimeException {

	/**
	 * base constructor.
	 */
	public RuntimeCryptoException() {
	}

	/**
	 * create a RuntimeCryptoException with the given message.
	 *
	 * @param message
	 *            the message to be carried with the exception.
	 */
	public RuntimeCryptoException(String message) {
		super(message);
	}
}
