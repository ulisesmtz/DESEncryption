
public class DES {
	
	
	private int[] DES(int[] plaintext, int[] key) throws Exception {
		if (plaintext.length != 64 || key.length != 64) {
			throw new Exception("Plaintext and key must be size 64");
		}
		
		int[] ciphertext = new int[64];
		return ciphertext;
	}
	

	public static void main(String[] args) {

	}

}
