
public class Encryption {
	
	private final static int MAX = 64; // max number of bits for DES
	
	// initial permutation of text (IP)
	private static byte[] IP = { 58, 50, 42, 34, 26, 18, 10, 2,
						  		 60, 52, 44, 36, 28, 20, 12, 4,
						  		 62, 54, 46, 38, 30, 22, 14, 6,
								 64, 56, 48, 40, 32, 24, 16, 8,
								 57, 49, 41, 33, 25, 17, 9,  1,
								 59, 51, 43, 35, 27, 19, 11, 3,
								 61, 53, 45, 37, 29, 21, 13, 5,
								 63, 55, 47, 39, 31, 23, 15, 7 };
	
	// final permutation of text (IP inverse)
	private static byte[] FP = { 40, 8, 48, 16, 56, 24, 64, 32,
								 39, 7, 47, 15, 55, 23, 63, 31,
								 38, 6, 46, 14, 54, 22, 62, 30,
								 37, 5, 45, 13, 53, 21, 61, 29,
								 36, 4, 44, 12, 52, 20, 60, 28,
								 35, 3, 43, 11, 51, 19, 59, 27,
								 34, 2, 42, 10, 50, 18, 58, 26,
								 33, 1, 41, 9,  49, 17, 57, 25 };
	
	// initial permutation of key
	private static final byte[] IP_KEY = { 57, 49, 41, 33, 25, 17, 9,
										   1,  58, 50, 42, 34, 26, 18,
										   10, 2,  59, 51, 43, 35, 27,
										   19, 11, 3,  60, 52, 44, 36,
										   63, 55, 47, 39, 31, 23, 15,
										   7,  62, 54, 46, 38, 30, 22,
										   14, 6,  61, 53, 45, 37, 29,
										   21, 13, 5,  28, 20, 12, 4 };
	
	private static int[] DES(int[] plaintext, int[] key) {
		
		// check if plaintext and key are size 64
		if (plaintext.length != MAX || key.length != MAX) {
			System.err.println("Plaintext and key must be size 64");
			return null;
		}
		
		// ciphertext is what will be returned, also size of 64
		int[] ciphertext = new int[MAX];
		int[] temp = new int[MAX];  // temporary array, will hold intermediary values for calculations
		
		// initial permutation
		for (int i = 0; i < MAX; i++) 
			temp[i] = plaintext[IP[i]-1];  // -1 to keep array in bounds
			

		
		return ciphertext;
	}
	

	public static void main(String[] args) {

		// test case in hw
		int[] plaintext = { 0, 0, 0, 0, 0, 0, 0, 1,
							0, 0, 1, 0, 0, 0, 1, 1, 
							0, 1, 0, 0, 0, 1, 0, 1, 
							0, 1, 1, 0, 0, 1, 1, 1,
							1, 0, 0, 0, 1, 0, 0, 1,
							1, 0, 1, 0, 1, 0, 1, 1, 
							1, 1, 0, 0, 1, 1, 0, 1,
							1, 1, 1, 0, 1, 1, 1, 1};
		
		int[] key = { 0, 0, 0, 1, 0, 0, 1, 1,
					  0, 0, 1, 1, 0, 1, 0, 0, 
					  0, 1, 0, 1, 0, 1, 1, 1, 
					  0, 1, 1, 1, 1, 0, 0, 1, 
					  1, 0, 0, 1, 1, 0, 1, 1,
					  1, 0, 1, 1, 1, 1, 0, 0, 
					  1, 1, 0, 1, 1, 1, 1, 1, 
					  1, 1, 1, 1, 0, 0, 0, 1 };
		
		// what should be returned
		int[] answer= { 1, 0, 0, 0, 0, 1, 0, 1,
						1, 1, 1, 0, 1, 0, 0, 0,
						0, 0, 0, 1, 0, 0, 1, 1,
						0, 1, 0, 1, 0, 1, 0, 0,
						0, 0, 0, 0, 1, 1, 1, 1,
						0, 0, 0, 0, 1, 0, 1, 0,
						1, 0, 1, 1, 0, 1, 0, 0,
						0, 0, 0, 0, 0, 1, 0, 1};
		
		int[] ciphertext = DES(plaintext, key);
		
		// check if answers are the same
		for (int i = 0; i < ciphertext.length; i++)
			if (answer[i] != ciphertext[i])
				System.out.println("Wrong!");
	}

}
