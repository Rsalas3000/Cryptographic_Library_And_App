import java.util.Arrays;

/**Sha3 reference in c:
 * https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 * @author Ricardo Salas
 *
 */
public class Sha3 {
	private static final int SIZE = 200;
	//200 bytes Sponge (length padding array)
	byte[] st_b = new byte[SIZE];
	private int pt;
	private int rsiz;
	private static int mdlen; 
	//specified 24 rounds
	private static final int KECCAKF_ROUNDS = 24;;

	private boolean ext = false, kmac = false;
	private static final byte[] KMAC_N = { (byte) 0x4B, (byte) 0x4D, (byte) 0x41, (byte) 0x43 }; // "KMAC" in ASCII
	private static final byte[] right_encode_0 = { (byte) 0x00, (byte) 0x01 }; // right_encode(0)

	// Representations of the constants; to populate 'RC' round contant array on
	// radix 16
	private static final long[] keccakf_rndc = new long[] { 0x0000000000000001L, 0x0000000000008082L,
			0x800000000000808aL, 0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L,
			0x8000000000008009L, 0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
			0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L, 0x8000000000008002L,
			0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L, 0x8000000000008080L,
			0x0000000080000001L, 0x8000000080008008L };

	// Initialize keccak fields and constants
	private static final int[] keccakf_rotc = new int[] { 1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25,
			43, 62, 18, 39, 61, 20, 44 };

	private static final int[] keccakf_piln = new int[] { 10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12,
			2, 20, 14, 22, 9, 6, 1 };

	// Keccak transform: 'rotate' with shifts
	private long ROTL64(long l, int i) {
		return (l << i) | (l >>> (64 - i));
	}

	/**
	 * The Keccak-𝑓 permutation Iterative construction: 24 rounds, each consisting
	 * of a sequence of 5 steps applied to the internal state: theta (𝜃), rho (𝜌),
	 * pi (𝜋), chi (𝜒) iota (𝜄).
	 * 
	 * @param b, the byte array
	 * 
	 */
	private void sha3_keccakf(byte[] b) {
		long[] st = new long[25]; // 64-bit words
		long[] bc = new long[5];

		// Converts the state before keccak operations.
				for (int i = 0; i < 25; i++) {
			int j = i * 8;
			st[i] = (((long) b[j] & 0xFFL)) 
					| (((long) b[j + 1] & 0xFFL) << 8) 
					| (((long) b[j + 2] & 0xFFL) << 16)
					| (((long) b[j + 3] & 0xFFL) << 24) 
					| (((long) b[j + 4] & 0xFFL) << 32)
					| (((long) b[j + 5] & 0xFFL) << 40) 
					| (((long) b[j + 6] & 0xFFL) << 48)
					| (((long) b[j + 7] & 0xFFL) << 56);
		}

		// The actual iteration for 24 rounds
		for (int r = 0; r < KECCAKF_ROUNDS; r++) {

			// theta (𝜃): linearly combines bits
			for (int i = 0; i < 5; i++) {
				bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
			}

			for (int i = 0; i < 5; i++) {
				long t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
				for (int j = 0; j < 25; j += 5) {
					st[j + i] ^= t;
				}
			}

			// pi & rho
			// pi (𝜋): permutes bits within slices (planes orthogonal to lanes).
			// rho (𝜌): cyclically shifts bits within individual lanes.
			long t = st[1];
			for (int i = 0; i < 24; i++) {
				int j = keccakf_piln[i];
				bc[0] = st[j];
				st[j] = ROTL64(t, keccakf_rotc[i]);
				t = bc[0];
			}

			// chi (𝜒): mixes highly nonlinear the bits within each row.
			for (int j = 0; j < 25; j += 5) {
				System.arraycopy(st, j, bc, 0, 5);
				for (int i = 0; i < 5; i++) {
					st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
				}
			}

			// iota (𝜄): adds asymmetric, round-specific constants to the (0,0) lane
			st[0] ^= keccakf_rndc[r];
		}

		// Return state to big endian after keccak operations.
		for (int i = 0; i < 25; i++) {
			int j = i * 8;
			long t = st[i];
			b[j] = (byte) (t & 0xFF);
			b[j + 1] = (byte) ((t >> 8) & 0xFF);
			b[j + 2] = (byte) ((t >> 16) & 0xFF);
			b[j + 3] = (byte) ((t >> 24) & 0xFF);
			b[j + 4] = (byte) ((t >> 32) & 0xFF);
			b[j + 5] = (byte) ((t >> 40) & 0xFF);
			b[j + 6] = (byte) ((t >> 48) & 0xFF);
			b[j + 7] = (byte) ((t >> 56) & 0xFF);
		}
	}

	/**
	 * intial Constructor 
	 * 
	 */
	public Sha3() {
	}
	
	/**
	 * Constructor with initial conditions
	 * 
	 * @param m
	 * 
	 */
	public Sha3(int m) {
		Arrays.fill(this.st_b, (byte) 0);
		mdlen = m;
		this.rsiz = SIZE - 2 * m;
		this.pt = 0;
	}

	/**
	 * Update the SHAKE256 sponge with a byte-oriented data portion.
	 * 
	 * @param data, input
	 * @param len,  the length of the data
	 * 
	 */
	public void SHAKE256_update(byte[] data, int len) {
		int j = this.pt;
		for (int i = 0; i < len; i++) {
			this.st_b[j++] ^= data[i];
			if (j >= this.rsiz) {
				sha3_keccakf(st_b);
				j = 0;
			}
		}
		this.pt = j;
	}

	/**
	 * absorbing to extensible squeezing.
	 * 
	 * @param c
	 * 
	 */
	public void SHAKE256_xof(boolean c) {
		if (c)
			st_b[pt] ^= 0x04;
		else
			st_b[pt] ^= 0x1F;
		st_b[rsiz - 1] ^= (byte) 0x80;
		sha3_keccakf(st_b);
		pt = 0;
	}

	/**
	 * Squeeze sponge Repeatedly to extract the total number of bytes needed.
	 * 
	 * @param out
	 * @param len
	 * 
	 */
	public void SHAKE_out(byte[] out, int len) {
		int j = pt;
		for (int i = 0; i < len; i++) {
			if (j >= rsiz) {
				sha3_keccakf(st_b);
				j = 0;
			}
			out[i] = st_b[j++];
		}
		pt = j;
	}
}
