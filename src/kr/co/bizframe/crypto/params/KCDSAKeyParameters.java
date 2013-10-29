/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

/**
 * 
 */
public class KCDSAKeyParameters
	extends AsymmetricKeyParameter {

	private KCDSAParameters    params;

	/**
	 * 
	 * @param isPrivate
	 * @param params
	 */
    public KCDSAKeyParameters(
        boolean         isPrivate,
        KCDSAParameters   params)
    {
        super(isPrivate);

        this.params = params;
    }

    /**
     * 
     * @return
     */
    public KCDSAParameters getParameters()
    {
        return params;
    }

}
