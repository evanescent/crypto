/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

/**
 * KCDSA 키 매개변수
 */
public class KCDSAKeyParameters
	extends AsymmetricKeyParameter {

	private KCDSAParameters    params;

	/**
	 * 비공개키 여부와 매개변수를 포함하는 생성자.
	 * 
	 * @param privateKey 비공개키 여부. 
	 *                   <code>true</code>면 비공개키, <code>false</code>면 공개키
	 * @param params 매개변수 
	 */
    public KCDSAKeyParameters(
        boolean         isPrivate,
        KCDSAParameters   params)
    {
        super(isPrivate);

        this.params = params;
    }

    /**
     * 매개변수를 반환한다.
     * 
     * @return 매개변수
     */
    public KCDSAParameters getParameters()
    {
        return params;
    }

}
