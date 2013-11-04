package kr.co.bizframe.crypto.params;


public class KCDSAKeyParameters
	extends AsymmetricKeyParameter {

	private KCDSAParameters    params;

    public KCDSAKeyParameters(
        boolean         isPrivate,
        KCDSAParameters   params)
    {
        super(isPrivate);

        this.params = params;
    }

    public KCDSAParameters getParameters()
    {
        return params;
    }

}
