
public class Crypto {
	
	private final static int MAX = 64; // max number of bits for DES
	
	// C and D are used to generate subkeys in each round. It is global
	// because round i uses round i-1 subkey 
	private static int[] C = new int[28];
	private static int[] D = new int[28];
	
	// initial permutation of text (IP)
	private static final int[] IP =  { 58, 50, 42, 34, 26, 18, 10, 2,
						  		 	   60, 52, 44, 36, 28, 20, 12, 4,
							  		   62, 54, 46, 38, 30, 22, 14, 6,
							  		   64, 56, 48, 40, 32, 24, 16, 8,
							  		   57, 49, 41, 33, 25, 17, 9,  1,
							  		   59, 51, 43, 35, 27, 19, 11, 3,
							  		   61, 53, 45, 37, 29, 21, 13, 5,
							  		   63, 55, 47, 39, 31, 23, 15, 7 };
	
	// final permutation of text (IP inverse)
	private static final int[] FP = { 40, 8, 48, 16, 56, 24, 64, 32,
								      39, 7, 47, 15, 55, 23, 63, 31,
								      38, 6, 46, 14, 54, 22, 62, 30,
								      37, 5, 45, 13, 53, 21, 61, 29,
								      36, 4, 44, 12, 52, 20, 60, 28,
								      35, 3, 43, 11, 51, 19, 59, 27,
								      34, 2, 42, 10, 50, 18, 58, 26,
								      33, 1, 41, 9,  49, 17, 57, 25 };
	
	// initial permutation of key
	private static final int[] IP_KEY =  { 57, 49, 41, 33, 25, 17, 9,
										   1,  58, 50, 42, 34, 26, 18,
										   10, 2,  59, 51, 43, 35, 27,
										   19, 11, 3,  60, 52, 44, 36,
										   63, 55, 47, 39, 31, 23, 15,
										   7,  62, 54, 46, 38, 30, 22,
										   14, 6,  61, 53, 45, 37, 29,
										   21, 13, 5,  28, 20, 12, 4 };
	
	// final permutation of each subkey generated in each round (48 bits)
	private static final int[] FP_KEY =  { 14, 17, 11, 24, 1,  5,  3,  28,
		                                   15, 6,  21, 10, 23, 19, 12, 4,
		                                   26, 8,  16, 7,  27, 20, 13, 2,
		                                   41, 52, 31, 37, 47, 55, 30, 40, 
		                                   51, 45, 33, 48, 44, 49, 39, 56, 
		                                   34, 53, 46, 42, 50, 36, 29, 32 };
	
	// expansion box (from 32 bits to 48 bits)
	private static final int[] EXPANSION =  { 32, 1,  2,  3,  4,  5,
		                                      4,  5,  6,  7,  8,  9,
		                                      8,  9,  10, 11, 12, 13,
		                                      12, 13, 14, 15, 16, 17,
		                                      16, 17, 18, 19, 20, 21,
		                                      20, 21, 22, 23, 24, 25,
		                                      24, 25, 26, 27, 28, 29,
		                                      28, 29, 30, 31, 32, 1  };
	// S-boxes as 2d array
	private static final int[][] SBOX = { 
		{ 14, 4,  13, 1,  2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0,  7,
		  0,  15, 7,  4,  14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3,  8,
		  4,  1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5,  0,
		  15, 12, 8,  2,  4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6,  13 },
		
		{ 15, 1,  8,  14, 6,  11, 3,  4,  9,  7,  2,  13, 12, 0,  5,  10,
		  3,  13, 4,  7,  15, 2,  8,  14, 12, 0,  1,  10, 6,  9,  11, 5,
		  0,  14, 7,  11, 10, 4,  13, 1,  5,  8,  12, 6,  9,  3,  2,  15,
		  13, 8,  10, 1,  3,  15, 4,  2,  11, 6,  7,  12, 0,  5,  14, 9 }, 
		  
		{ 10, 0,  9,  14, 6,  3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8,
		  13, 7,  0,  9,  3,  4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1,
		  13, 6,  4,  9,  8,  15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7,
		  1,  10, 13, 0,  6,  9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12 },
		  
		{ 7,  13, 14, 3,  0,  6,  9,  10, 1,  2,  8,  5,  11, 12, 4,  15,
		  13, 8,  11, 5,  6,  15, 0,  3,  4,  7,  2,  12, 1,  10, 14, 9,
		  10, 6,  9,  0,  12, 11, 7,  13, 15, 1,  3,  14, 5,  2,  8,  4,
		  3,  15, 0,  6,  10, 1,  13, 8,  9,  4,  5,  11, 12, 7,  2,  14 },
		  
		{ 2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0,  14, 9,
		  14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9,  8,  6,
		  4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3,  0,  14,
		  11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4,  5,  3 },
		  
		{ 12, 1,  10, 15, 9,  2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11,
		  10, 15, 4,  2,  7,  12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8,
		  9,  14, 15, 5,  2,  8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6,
		  4,  3,  2,  12, 9,  5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13 },
		  
		{ 4,  11, 2,  14, 15, 0,  8,  13, 3,  12, 9,  7,  5,  10, 6,  1,
		  13, 0,  11, 7,  4,  9,  1,  10, 14, 3,  5,  12, 2,  15, 8,  6,
		  1,  4,  11, 13, 12, 3,  7,  14, 10, 15, 6,  8,  0,  5,  9,  2,
		  6,  11, 13, 8,  1,  4,  10, 7,  9,  5,  0,  15, 14, 2,  3,  12 }, 
		  
		{ 13, 2,  8,  4,  6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7,
		  1,  15, 13, 8,  10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2,
		  7,  11, 4,  1,  9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8,
		  2,  1,  14, 7,  4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11 }
		};
	
	
	// permutation for end of mangler function
	private static final int[] P = { 16, 7,  20, 21,
									 29, 12, 28, 17,
									 1,  15, 23, 26,
									 5,  18, 31, 10,
									 2,  8,  24, 14,
									 32, 27, 3,  9,
									 19, 13, 30, 6,
									 22, 11, 4,  25 };
	
	
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
	 * @param right the right half of the sub key
	 * @param subkey the key for that round
	 * @return new right half of subkey
	 */
	private static int[] mangler(int[] right, int[] subkey) {
		int[] expandedRight = new int[48];
		for (int i = 0; i < 48; i++) 
			expandedRight[i] = right[EXPANSION[i]-1];
		
		// xor the expandedRight with subkey and store in variable xor
		int[] xor = new int[48];
		for (int i = 0; i < 48; i++)
			xor[i] = expandedRight[i] ^ subkey[i];
		
		
		
		// S-boxes are applied in this method and stored in output
		int output[] = new int[32];
		
		for(int i=0 ; i < 8 ; i++) {
			// row bits are found from bit 0 and 5
			int[] row = new int [2];
			row[0] = xor[6*i];
			row[1] = xor[(6*i)+5];
			String sRow = row[0] + "" + row[1];

			// column bits are bits 1-4 (inclusive)
			int column[] = new int[4];
			column[0] = xor[(6*i)+1];
			column[1] = xor[(6*i)+2];
			column[2] = xor[(6*i)+3];
			column[3] = xor[(6*i)+4];
			String sColumn = column[0] +""+ column[1] +""+ column[2] +""+ column[3];

			// convert to decimal
			int iRow = Integer.parseInt(sRow, 2);
			int iColumn = Integer.parseInt(sColumn, 2);
			int x = SBOX[i][(iRow*16) + iColumn];

			String s = Integer.toBinaryString(x);

			// pad to make sure its 4 bits long
			while(s.length() < 4) {
				s = "0" + s;
			}
			// The binary bits are appended to the output
			for(int j=0 ; j < 4 ; j++) {
				output[(i*4) + j] = Integer.parseInt(s.charAt(j) + "");
			}
		}
		
		// permute
		int[] finalOutput = new int[32];
		for(int i=0 ; i < 32 ; i++) {
			finalOutput[i] = output[P[i]-1];
		}

		return finalOutput;
			
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
		
		
		// combine left and right in reverse order, and perform final permutation
		int[] leftRight = new int[MAX];
		for (int i = 0; i < MAX; i++) {
			if (i < MAX/2)
				leftRight[i] = right[i];
			else
				leftRight[i] = left[i-32];
		}
		
		for (int i = 0; i < MAX; i++)
			ciphertext[i] = leftRight[FP[i]-1];

		
		return ciphertext;
	}
	
	/** Driver program to implement CBC
	 * @param plaintext the message to be encrypted
	 * @param key the key to encrypt
	 * @return integer array with ascii values
	 */
	private static int CBC(String plaintext, String key) {
		
	}
	

	public static void main(String[] args) {

	}

}
