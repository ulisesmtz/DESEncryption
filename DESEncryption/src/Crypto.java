
public class Crypto {
	
	private final static int MAX = 64; // max number of bits for DES
	
	// C and D are used to generate subkeys in each round. It is global
	// because round i uses round i-1 subkey 
	private static int[] C = new int[28];
	private static int[] D = new int[28];
	
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
	
	// final permutation of each subkey generated in each round (48 bits)
	private static final byte[] FP_KEY = { 14, 17, 11, 24, 1,  5,  3,  28,
		                                   15, 6,  21, 10, 23, 19, 12, 4,
		                                   26, 8,  16, 7,  27, 20, 13, 2,
		                                   41, 52, 31, 37, 47, 55, 30, 40, 
		                                   51, 45, 33, 48, 44, 49, 39, 56, 
		                                   34, 53, 46, 42, 50, 36, 29, 32 };
	
	/**
	 * @param n the number of times to shift left
	 * @param array the array to be shifted
	 * @return modified int array with elements shifted left n times
	 */
	private static int[] shiftLeft(int n, int[] array) {
		for (int i = 0; i < n; i++) {
			int temp = array[0];
			for (int j = 0; j < array.length-1; j++)
				array[j] = array[j+1];
			array[array.length-1] = temp;  // last element gets first element in original array
		}
		return array;
	}
	
	/** Generate the round key for a specific round
	 * @param round the round number (1-16)
	 * @param key the original key
	 * @return integer array that contains subkey
	 */
	private static int[] getRoundKey(int round, int key[]) {
		int[] subkey = new int[48];  // subkey of 48 bits will be returned from method
		
		// C naught (Co) and D naught (Do) will hold the new values for C and D
		int[] Co = new int[28];
		int[] Do = new int[28];
		int shifts;  // will hold how many shifts will happen depending on round number
		
		if (round == 1 || round == 2 || round == 9 || round == 16)
			shifts = 1;
		else 
			shifts = 2;
		
		Co = shiftLeft(shifts, C);
		Do = shiftLeft(shifts, D);
		
		int[] CD = new int[56];  // holds concatenation of Co and Do
		
		for (int i = 0; i < CD.length; i++)
			if (i < CD.length/2)    // copy from Co
				CD[i] = Co[i];
			else					// copy from Do
				CD[i] = Do[i-(CD.length/2)];
		
		// final permutation of subkey
		for (int i = 0; i < subkey.length; i++) 
			subkey[i] = CD[FP_KEY[i]-1];
		
		C = Co;
		D = Do;
		return subkey;
	}
	
	/** Expands right to 48 bits, xor the expanded right with the subkey, and use S Boxes
	 * @param right the right half of teh sub key
	 * @param subkey the key for that round
	 * @return new right half of subkey
	 */
	private static int[] mangler(int[] right, int[] subkey) {
		
		return null;
	}
	
	/** Driver method for this program. 
	 * @param plaintext message to be encrypted, 64 bits
	 * @param key the key to encrypt the data, 64 bits
	 * @return integer array with ciphertext filled with 0 and 1
	 */
	private static int[] DES(int[] plaintext, int[] key) {
		
		// check if plaintext and key are size 64
		if (plaintext.length != MAX || key.length != MAX) {
			System.err.println("Plaintext and key must be of size 64");
			return null;
		}
		
		// ciphertext is what will be returned, also size of 64
		int[] ciphertext = new int[MAX];
		
		// left and right will hold their half of the subkey, respectively
		int[] left = new int[MAX/2]; 
		int[] right = new int[MAX/2];
		
		// initial permutation of plaintext and store half in left array, other half in right array
		for (int i = 0; i < MAX; i++) {
			if (i < 32)
				left[i] = plaintext[IP[i]-1];  
			else
				right[i-32] = plaintext[IP[i]-1];
		}
		
		// initial permutation of key, store first half (28 bits) in C, other half in D
		for (int i = 0; i < 56; i++) {
			if (i < 28)
				C[i] = key[IP_KEY[i]-1];
			else
				D[i-28] = key[IP_KEY[i]-1];
		}
		
		// begin the 16 rounds of encryption
		for (int i = 1; i <= 16; i++) {
			int subkey[] = getRoundKey(i, key);
			int[] newRight = mangler(right, subkey);
			
			// left = right and right = left xor newRight
			int[] temp = new int[left.length];
			
			for (int j = 0; j < left.length; j++)
				temp[j] = left[j] ^ newRight[j];
			
			left = right;
			right = temp;
			
		}
		
		// combine left and right, and perform final permutation
		int[] leftRight = new int[MAX];
		for (int i = 0; i < MAX; i++) {
			if (i < MAX/2)
				leftRight[i] = left[i];
			else
				leftRight[i] = right[i-32];
		}
		
		for (int i = 0; i < MAX; i++)
			ciphertext[i] = leftRight[FP[i]-1];

		
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
