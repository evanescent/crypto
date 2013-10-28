/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

/**
 * this exception is thrown whenever we find something we don't expect in a
 * message.
 */
public class InvalidCipherTextException extends CryptoException {

	/**
	 * base constructor.
	 */
	public InvalidCipherTextException() {
	}

	/**
	 * create a InvalidCipherTextException with the given message.
	 *
	 * @param message
	 *            the message to be carried with the exception.
	 */
	public InvalidCipherTextException(String message) {
		super(message);
	}
}
