package kr.co.bizframe.crypto.test.unit.digests;

import java.io.FileInputStream;

import kr.co.bizframe.crypto.digests.SHA1Digest;
import kr.co.bizframe.crypto.util.ByteUtil;

public class SHA1Test {


	public void test(){

		byte[] source = "abc".getBytes();
		//byte[] source = "abcaafdfdfdfdfadfdfdfdfdfdfadfdfdfdfdfadfdfdfdfdfdfdfdafdfdf".getBytes();
		//byte[] source = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes();
		SHA1Digest digest = new SHA1Digest();
		digest.update(source, 0, source.length);

		byte[] output = new byte[20];
		digest.doFinal(output, 0);

		System.out.println("sha1 hash = "+ ByteUtil.toHexString(output));

	}



	public void testLarge(){

		SHA1Digest digest = new SHA1Digest();
		String fn = "D:/data/zip/aa.mp3";
		try{
			int read = 0;
			byte[] buf = new byte[1024*8];
			FileInputStream fis = new FileInputStream(fn);
			while( (read = fis.read(buf)) != -1){
				digest.update(buf, 0, read);
			}

			byte[] out = new byte[20];
			digest.doFinal(out, 0);

			System.out.println("sha1 hash = "+ ByteUtil.toHexString(out));

		}catch(Exception e){
			e.printStackTrace();
		}
	}



	public static void main(String[] argv){

		SHA1Test st = new SHA1Test();
		st.test();
		//st.testLarge();
	}
}
