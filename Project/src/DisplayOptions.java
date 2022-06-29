import java.awt.FileDialog;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;
import javax.swing.JFrame;

/**
 * Display to user involving options to choose from consisting of
 * several methods involving SHA-3 derived function KMACXOF256
 * and ECDHIES encryption and Schnorr signatures.
 * 
 * @author Ricardo Salas
 *
 */
public class DisplayOptions {
	static Scanner input = new Scanner(System.in);
	private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

	public DisplayOptions() {
		HomePrompt();
	}

	/**
	 * Home prompt deciding whether user chooses SHA-3 derived function KMACXOF256
	 * or ECDHIES encryption and Schnorr signatures
	 * 
	 */
	public static void HomePrompt() {
		int option;

		while (true) {
			System.out.println();
			System.out.println("\t\t\t\t৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩");
			System.out.println("\t\t\t\tCryptographic Library");
			System.out.println("\t\t\t\t৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩");
			System.out.println();
			System.out.println("\t\t\t(1) SHA-3 derived function KMACXOF256");
			System.out.println("\t\t\t(2) ECDHIES encryption and Schnorr signatures");
			System.out.println();
			System.out.println("\t\t\t\tChoose your algorithm");
			System.out.println();
			while (!input.hasNextInt()) {
				System.out.println("Invalid option, please try again.");
				System.out.print("Enter your option (1-2): ");
				input.nextLine();
			}
			option = input.nextInt();
			homeOptions(option);
			System.out.println("\n");

		}
	}

	/**
	 * (1) SHA-3 derived function KMACXOF256 (2) ECDHIES encryption and Schnorr
	 * signatures
	 * 
	 * @param option
	 * 
	 */
	private static void homeOptions(int option) {
		switch (option) {
		case 1:
			homeCase1();
		case 2:
			homeCase2();
		}
	}

	/**
	 * Main menu of the application
	 * 
	 */
	public static void homeCase1() {
		int option;

		while (true) {
			System.out.println("৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩\n");
			System.out.println();
			System.out.println("\t(1) Compute a plain cryptographic hash of a given file");
			System.out.println("\t(2) Compute a plain cryptographic hash of input text");
			System.out.println("\t(3) Encrypt a given file symmetrically under a given passphrase");
			System.out.println("\t(4) Decrypt a given file symmetrically under a given passphrase");
			System.out.println("\t(5) Compute an authentication tag (MAC) of a given file under a given passphrase");
			System.out.println();
			System.out.println("৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩\n");
			System.out.print("Enter your option (1-5): ");
			while (!input.hasNextInt()) {
				System.out.println("Invalid option, please try again.");
				System.out.print("Enter your option (1-5): ");
				input.nextLine();
			}
			option = input.nextInt();
			optionFunction1(option);
			System.out.println("\n");

		}
	}

	/**
	 * Show all options for the application s
	 * 
	 * @param option, the options of all application s *
	 */

	private static void optionFunction1(int option) {
		switch (option) {
		case 1: // Compute a plain cryptographic hash of a given file
			hashFileInput();
			HomePrompt();
		case 2: // Compute a plain cryptographic hash of input text
			hashInputText();
			HomePrompt();
		case 3: // Encrypt a given file symmetrically under a given passphrase
			encryptSymmetric();
			HomePrompt();
		case 4: // Decrypt a given file symmetrically under a given passphrase
			decryptSymmetric();
			HomePrompt();
		case 5: // Compute an authentication tag (MAC) of a given file under a given passphrase
			computeMac();
			HomePrompt();
		}
	}

	public static void homeCase2() {
		int option;

		while (true) {
			System.out.println("৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩\n");
			System.out.println("\t(1) Generate an elliptic key pair file from a given passphrase");
			System.out.println("\t(2) Encrypt a data file under a given elliptic public key file");
			System.out.println("\t(3) Decrypt a given elliptic-encrypted file from a given password");
			System.out.println("\t(4) Encrypt text input under a given elliptic public key");
			System.out.println("\t(5) Decrypt an elliptic-encrypted text input from a given password");
			System.out.println("\t(6) Sign a given file from a given password");
			System.out.println("\t(7) Verify a given data file and its signature file under a given public key file");
			System.out.println("\t(8) Exit");
			System.out.println("৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩\n");
			System.out.println();
			System.out.print("Enter your option (1-8): ");
			while (!input.hasNextInt()) {
				System.out.println("Invalid option, please try again.");
				System.out.print("Enter your option (1-8): ");
				input.nextLine();
			}
			option = input.nextInt();
			System.out.println("৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩\n");
			optionFunction2(option);
			System.out.println("\n");

		}
	}

	private static void optionFunction2(int option) {
		switch (option) {
		case 1: // Generate an elliptic key pair file from a given passphrase
			generateEllipticKey();
			HomePrompt();
		case 2: // Encrypt a data file under a given elliptic public key file
			encryptElliptic();
			HomePrompt();
		case 3: // Decrypt a data file under a given elliptic public key file
			decryptElliptic();
			HomePrompt();
		case 4: // Encrypt text input under a given elliptic public key file
			encryptEllipticInputText();
			HomePrompt();
		case 5: // Decrypt an elliptic-encrypted text input from a given password
			decryptEllipticInputText();
			HomePrompt();
		case 6: // Sign a given file from a given password
			signFile();
			HomePrompt();
		case 7: // Verify a given data file and its signature file under a given public key file
			verifySignature();
			HomePrompt();
		case 8: // exit the application
			System.out.println("\nThank you!!");
			System.out.println(
					"\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> End of the Application <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
			System.exit(1);
		default: // invalid input
			System.out.println("\nInvalid option, please try again!");
			HomePrompt();
		}
	}

	/**
	 * Compute a plain cryptographic hash of a given file h <- KMACXOF256(“”, m,
	 * 512, “D”)
	 * 
	 */
	private static void hashFileInput() {
		System.out.println("Compute a plain cryptographic hash of a given file.\n");
		System.out.println("Please select the input file.");
		byte[] filename = openFile();
		if (filename == null) {
			System.out.println("\nYou did not select any file.\n");
		} else {
			// h = KMACXOF256(“”, m, 512, “D”)
			byte[] h = KMACXOF256.KMACXOF256_cal("".getBytes(), filename, 512, "D".getBytes());

			String outputFile = saveFile(h, true);
			System.out.println("৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩\n");
			if (outputFile.equals("")) {
				System.out.println("File could not be written, try again.");
			} else {
				System.out.println("Save output file as: " + outputFile);
			}
		}
	}

	/**
	 * Compute a plain cryptographic hash of input text Computing a cryptographic
	 * hash h of a byte array m: h <- KMACXOF256(“”, m, 512, “D”)
	 * 
	 */
	private static void hashInputText() {
		System.out.println("Enter the string you want to hash:");
		input = new Scanner(System.in); // instantiate new scanner to flush out \n characters
		String text = input.nextLine();
		byte[] inputText = text.getBytes();
		// h <- KMACXOF256(“”, m, 512, “D”)
		byte[] h = KMACXOF256.KMACXOF256_cal("".getBytes(), inputText, 512, "D".getBytes());
		StringBuilder hashText = new StringBuilder();
		for (byte b : h) {
			int v = b & 0xFF;
			hashText.append(HEX_ARRAY[v >>> 4]);
			hashText.append(HEX_ARRAY[v & 0x0F]);
			// hashText.append(" ");
		}
		String hashOutput = hashText.toString();
		System.out.println("৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩\n");
		System.out.println("Your text \"" + text + "\" hashed to ->\n" + hashOutput + "\n\t");
	}

	/**
	 * Encrypting a byte array m symmetrically under passphrase pw: z <- Random(512)
	 * (ke || ka) <- KMACXOF256(z || pw, “”, 1024, “S”) c <- KMACXOF256(ke, “”, |m|,
	 * “SKE”) xor m t <- KMACXOF256(ka, m, 512, “SKA”) symmetric cryptogram: (z, c,
	 * t)
	 * 
	 * @a
	 */
	private static void encryptSymmetric() {
		System.out.println("Encrypt a given file symmetrically under a given passphrase.\n");
		System.out.println("Please select the input file.");
		byte[] filename = openFile();
		if (filename == null) {
			System.out.println("\nYou did not select any file.\n");
		} else {
			System.out.println("Please enter the passphrase: ");
			byte[] pw = input.next().getBytes();

			// z <- Random(512)
			byte[] z = new byte[64];
			Random randomNo = new Random();
			randomNo.nextBytes(z);

			// (ke || ka) <- KMACXOF256(z || pw, “”, 1024, “S”)
			byte[] z_and_pw = KMACXOF256.concat(z, pw);
			byte[] ke_and_ka = KMACXOF256.KMACXOF256_cal(z_and_pw, new byte[0], 1024, "S".getBytes());
			byte[] ke = Arrays.copyOfRange(ke_and_ka, 0, 64);
			byte[] ka = Arrays.copyOfRange(ke_and_ka, 64, ke_and_ka.length);

			// c <- KMACXOF256(ke, “”, |m|, “SKE”) xor m
			byte[] c = KMACXOF256.KMACXOF256_cal(ke, "".getBytes(), filename.length * 8, "SKE".getBytes());
			for (int i = 0; i < c.length; i++) {
				c[i] = (byte) (c[i] ^ filename[i]);
			}

			// t <- KMACXOF256(ka, m, 512, “SKA”)
			byte[] t = KMACXOF256.KMACXOF256_cal(ka, filename, 512, "SKA".getBytes());

			// symmetric cryptogram: (z, c, t)
			String response = saveFile(z, true);
			System.out.println("৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩\n");
			if (response.equals("")) {
				System.out.println("File could not be written, try again.");
			} else {
				writeToFile(c, response);
				writeToFile(t, response);
				System.out.println("Save encrypt file as: " + response);
			}
		}
	}

	/**
	 * Decrypt a given file symmetrically under a given passphrase Decrypting a
	 * symmetric cryptogram (z, c, t) under passphrase pw: (ke || ka) <-
	 * KMACXOF256(z || pw, “”, 1024, “S”) m <- KMACXOF256(ke, “”, |c|, “SKE”) xor c
	 * t’ <- KMACXOF256(ka, m, 512, “SKA”) accept if, and only if, t’ = t
	 * 
	 */
	private static void decryptSymmetric() {
		System.out.println("Decrypt a given file symmetrically under a given passphrase.\n");
		System.out.println("Please select the symmetric encrypted file to decrypt.");

		// split input from encrypted file: symmetric cryptogram: (z, c, t) -> line by
		// line
		String[] line = getLine();

		if (line == null) {
			System.out.println("\nYou did not select any file.\n");
		} else {
			System.out.println("Please enter the same passphrase used to encrypt file: ");
			byte[] pw = input.next().getBytes();
			byte[] z = convertHexToByte(line[0]);
			byte[] c = convertHexToByte(line[1]);
			byte[] t = convertHexToByte(line[2]);

			// (ke || ka) <- KMACXOF256(z || pw, “”, 1024, “S”)
			byte[] ke_and_ka = KMACXOF256.KMACXOF256_cal(KMACXOF256.concat(z, pw), "".getBytes(), 1024, "S".getBytes());
			byte[] ke = Arrays.copyOfRange(ke_and_ka, 0, 64);
			byte[] ka = Arrays.copyOfRange(ke_and_ka, 64, ke_and_ka.length);

			// m <- KMACXOF256(ke, “”, |c|, “SKE”) xor c
			byte[] m = KMACXOF256.KMACXOF256_cal(ke, "".getBytes(), c.length * 8, "SKE".getBytes());
			for (int i = 0; i < m.length; i++) {
				m[i] = (byte) (m[i] ^ c[i]);
			}

			// t’ <- KMACXOF256(ka, m, 512, “SKA”)
			byte[] t_bar = KMACXOF256.KMACXOF256_cal(ka, m, 512, "SKA".getBytes());

			System.out.println("৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩\n");
			// accept if, and only if, t’ = t
			if (Arrays.equals(t, t_bar)) {
				System.out.println("Decrypted/Original Text: ");
				System.out.println(new String(m));
				String outputFile = saveFile(m, false);
				System.out.println("Save decrypt file as: " + outputFile);
			} else {
				System.out.println("Wrong Password -> Error to decrypt the text!!");
			}
		}
	}

	/**
	 * Compute an authentication tag (MAC) of a given file under a given passphrase.
	 * 
	 */
	private static void computeMac() {
		System.out.println("Compute an authentication tag (MAC) of a given file under a given passphrase\n");
		System.out.println("Please select the input file.");
		byte[] filename = openFile();
		if (filename == null) {
			System.out.println("\nYou did not select any file.\n");
		} else {
			System.out.println("Please enter the passphrase for calculating the MAC");
			byte[] pw = input.next().getBytes();

			byte[] t = KMACXOF256.KMACXOF256_cal(pw, filename, 512, "T".getBytes());
			String outputFile = saveFile(t, true);
			System.out.println("৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩\n");
			if (outputFile.equals("")) {
				System.out.println("File could not be written, try again.");
			} else {
				System.out.println("Save output file as: " + outputFile);
			}
		}
	}

	/**
	 * Generating a (Schnorr/ECDHIES) key pair from passphrase pw V <- s*G key pair:
	 * (s, V)
	 * 
	 */
	private static void generateEllipticKey() {
		System.out.println("Generate an elliptic key pair file from a given passphrase.\n");
		System.out.println("Please enter the passphrase to generate a key pair: ");
		// byte[] pw = input.next().getBytes();
		String pwd = input.next();
		System.out.println(pwd);

		// s <- KMACXOF256(pw, “”, 512, “K”); s <- 4s
		byte[] s_byte = KMACXOF256.KMACXOF256_cal(pwd.getBytes(), "".getBytes(), 512, "K".getBytes());

		byte[] temp = new byte[1];
		temp[0] = (byte) 0x00;
		s_byte = KMACXOF256.concat(temp, s_byte);
		BigInteger s = new BigInteger(s_byte);
		s = s.multiply(new BigInteger("4"));

		// V <- s*G
		EllipticCurve G = new EllipticCurve(new BigInteger("4"));
		EllipticCurve V = G.mulByScalar(s);

		// key pair: (s, V)
		byte[] x = V.getX().toByteArray();
		byte[] y = V.getY().toByteArray();

		String path = saveFile(x, true);
		System.out.println("৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩\n");
		if (path.equals("")) {
			System.out.println("Key unable to be saved.");
		} else {
			writeToFile(y, path);
			System.out.println("Public key saved at: " + path);
		}
	}

	/**
	 * Encrypt a data file under a given elliptic public key file Encrypting a byte
	 * array m under the (Schnorr/ECDHIES) public key V: k <- Random(512); k <- 4k W
	 * <- k*V; Z <- k*G (ke || ka) <- KMACXOF256(Wx, “”, 1024, “P”) c <-
	 * KMACXOF256(ke, “”, |m|, “PKE”) xor m t <- KMACXOF256(ka, m, 512, “PKA”)
	 * cryptogram: (Z, c, t)
	 * 
	 */

	private static void encryptElliptic() {
		System.out.println("Encrypt a data file under a given elliptic public key file.\n");
		System.out.println("Please select the input file.");
		byte[] filename = openFile();
		if (filename == null) {
			System.out.println("\nYou did not select any file.\n");
		} else {
			System.out.println("Please select the elliptic key file.");
			String[] publicKey = getLine();
			if (publicKey == null) {
				System.out.println("\nYou did not select any file.\n");
			} else {

				// k = Random(512); k = 4k
				byte[] byte_k = new byte[64];
				Random rand = new Random();
				rand.nextBytes(byte_k);

				byte[] temp = new byte[1];
				temp[0] = (byte) 0x00;

				byte_k = KMACXOF256.concat(temp, byte_k);
				BigInteger k = new BigInteger(byte_k);
				k = k.multiply(new BigInteger("4"));

				// W = k*V; Z = k*G
				EllipticCurve G = new EllipticCurve(new BigInteger("4"));
				EllipticCurve V = new EllipticCurve(new BigInteger(convertHexToByte(publicKey[0])),
						new BigInteger(convertHexToByte(publicKey[1])));
				EllipticCurve W = V.mulByScalar(k);
				EllipticCurve Z = G.mulByScalar(k);

				// (ke || ka) = KMACXOF256(Wx, “”, 1024, “P”)
				byte[] keka = KMACXOF256.KMACXOF256_cal(W.getX().toByteArray(), "".getBytes(), 1024, "P".getBytes());
				byte[] ke = Arrays.copyOfRange(keka, 0, 64);
				byte[] ka = Arrays.copyOfRange(keka, 64, keka.length);

				// c = KMACXOF256(ke, “”, |m|, “PKE”) xor m
				byte[] c = KMACXOF256.KMACXOF256_cal(ke, "".getBytes(), filename.length * 8, "PKE".getBytes());
				for (int i = 0; i < c.length; i++) {
					c[i] = (byte) (c[i] ^ filename[i]);
				}

				// t = KMACXOF256(ka, m, 512, “SKA”)
				byte[] t = KMACXOF256.KMACXOF256_cal(ka, filename, 512, "PKA".getBytes());

				String response = saveFile(Z.getX().toByteArray(), true);
				System.out.println("৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩\n");
				if (response.equals("")) {
					System.out.println("Cryptogram unable to be saved");
				} else {
					writeToFile(Z.getY().toByteArray(), response);
					writeToFile(c, response);
					writeToFile(t, response);
					System.out.println("File encrypted at: " + response);
				}
			}
		}
	}

	/**
	 * Decrypt a given elliptic-encrypted file from a given password Decrypting a
	 * cryptogram (Z, c, t) under passphrase pw: s <- KMACXOF256(pw, “”, 512, “K”);
	 * s <- 4s W <- s*Z (ke || ka) <- KMACXOF256(Wx, “”, 1024, “P”) m <-
	 * KMACXOF256(ke, “”, |c|, “PKE”) xor c t’ <- KMACXOF256(ka, m, 512, “PKA”)
	 * accept if, and only if, t’ = t
	 * 
	 */

	private static void decryptElliptic() {
		System.out.println("Decrypt a given elliptic-encrypted file from a given password.\n");
		System.out.println("Please select the elliptic encrypted file to decrypt.");
		String[] line = getLine();

		if (line == null) {
			System.out.println("\nYou did not select any file.\n");
		} else {
			System.out.println("Please type the passphrase used to encrypt the file");
			byte[] pw = input.next().getBytes();

			// s = KMACXOF256(pw, “”, 512, “K”); s = 4s
			byte[] byte_s = KMACXOF256.KMACXOF256_cal(pw, "".getBytes(), 512, "K".getBytes());

			byte[] temp = new byte[1];
			temp[0] = (byte) 0x00;
			byte_s = KMACXOF256.concat(temp, byte_s);
			BigInteger s = new BigInteger(byte_s);
			s = s.multiply(new BigInteger("4"));

			// W = s*Z
			EllipticCurve Z = new EllipticCurve(new BigInteger(convertHexToByte(line[0])),
					new BigInteger(convertHexToByte(line[1])));
			EllipticCurve W = Z.mulByScalar(s);

			// (ke || ka) = KMACXOF256(Wx, “”, 1024, “P”)
			byte[] keka = KMACXOF256.KMACXOF256_cal(W.getX().toByteArray(), "".getBytes(), 1024, "P".getBytes());
			byte[] ke = Arrays.copyOfRange(keka, 0, 64);
			byte[] ka = Arrays.copyOfRange(keka, 64, keka.length);

			// m = KMACXOF256(ke, “”, |c|, "PKE”) xor c
			byte[] c = convertHexToByte(line[2]);
			byte[] m = KMACXOF256.KMACXOF256_cal(ke, "".getBytes(), c.length * 8, "PKE".getBytes());
			for (int i = 0; i < m.length; i++) {
				m[i] = (byte) (m[i] ^ c[i]);
			}

			// t’ = KMACXOF256(ka, m, 512, “PKA”)
			byte[] t_prime = KMACXOF256.KMACXOF256_cal(ka, m, 512, "PKA".getBytes());

			System.out.println("৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩\n");
			// accept if, and only if, t’ = t
			if (Arrays.equals(convertHexToByte(line[3]), t_prime)) {
				System.out.println("Decrypted/Original Text: ");
				System.out.println(new String(m));
				String outputFile = saveFile(m, false);
				System.out.println("Saved decrypted file at: " + outputFile);
			} else {
				System.out.println("Wrong password -> Error decrypting the text!!");
			}
		}
	}

	/**
	 * Encrypt text input under a given elliptic public key Encrypt/decrypt text
	 * input by the user directly to the app instead of having to be read from a
	 * file.
	 * 
	 */
	private static void encryptEllipticInputText() {

		System.out.println("Encrypt text input under a given elliptic public key");

		///////////////////////////////////////////
		////////// Generate the key pair //////////
		///////////////////////////////////////////

		System.out.println("Please enter the passphrase to generate a key pair: ");
		String pwd = input.next();
		System.out.println(pwd);

		// s <- KMACXOF256(pw, “”, 512, “K”); s <- 4s
		byte[] s_byte = KMACXOF256.KMACXOF256_cal(pwd.getBytes(), "".getBytes(), 512, "K".getBytes());

		byte[] temp = new byte[1];
		temp[0] = (byte) 0x00;
		s_byte = KMACXOF256.concat(temp, s_byte);
		BigInteger s = new BigInteger(s_byte);
		s = s.multiply(new BigInteger("4"));

		// V <- s*G
		EllipticCurve G = new EllipticCurve(new BigInteger("4"));
		EllipticCurve V = G.mulByScalar(s);

		// key pair: (s, V)
		byte[] x = V.getX().toByteArray();
		byte[] y = V.getY().toByteArray();

		StringBuilder xText = new StringBuilder();
		for (byte b : x) {
			int v = b & 0xFF;
			xText.append(HEX_ARRAY[v >>> 4]);
			xText.append(HEX_ARRAY[v & 0x0F]);
		}
		String KeyX = xText.toString();

		StringBuilder yText = new StringBuilder();
		for (byte b : y) {
			int v = b & 0xFF;
			yText.append(HEX_ARRAY[v >>> 4]);
			yText.append(HEX_ARRAY[v & 0x0F]);
		}
		String KeyY = yText.toString();
		String[] publicKey = new String[] { KeyX, KeyY };

		//////////////////////////////////////////////
		////////// Input Message to Encrypt //////////
		//////////////////////////////////////////////

		System.out.println("Enter the string you want to encrypt: ");
		input = new Scanner(System.in);
		String message = input.nextLine();
		byte[] message_b = message.getBytes();

		//////////////////////////////////////////////
		/////////////// Encrypt Method ///////////////
		//////////////////////////////////////////////

		// k = Random(512); k = 4k
		byte[] byte_k = new byte[64];
		Random rand = new Random();
		rand.nextBytes(byte_k);

		byte_k = KMACXOF256.concat(temp, byte_k);
		BigInteger k = new BigInteger(byte_k);
		k = k.multiply(new BigInteger("4"));

		// W = k*V; Z = k*G
		EllipticCurve newV = new EllipticCurve(new BigInteger(convertHexToByte(publicKey[0])),
				new BigInteger(convertHexToByte(publicKey[1])));
		EllipticCurve W = newV.mulByScalar(k);
		EllipticCurve Z = G.mulByScalar(k);

		// (ke || ka) = KMACXOF256(Wx, “”, 1024, “P”)
		byte[] keka = KMACXOF256.KMACXOF256_cal(W.getX().toByteArray(), "".getBytes(), 1024, "P".getBytes());
		byte[] ke = Arrays.copyOfRange(keka, 0, 64);
		byte[] ka = Arrays.copyOfRange(keka, 64, keka.length);

		// c = KMACXOF256(ke, “”, |m|, “PKE”) xor m
		byte[] c = KMACXOF256.KMACXOF256_cal(ke, "".getBytes(), message_b.length * 8, "PKE".getBytes());
		for (int i = 0; i < c.length; i++) {
			c[i] = (byte) (c[i] ^ message_b[i]);
		}

		StringBuilder z_x_Text = new StringBuilder();
		for (byte b : Z.getX().toByteArray()) {
			int v = b & 0xFF;
			z_x_Text.append(HEX_ARRAY[v >>> 4]);
			z_x_Text.append(HEX_ARRAY[v & 0x0F]);
		}
		String z_x_Hex = z_x_Text.toString();

		StringBuilder z_y_Text = new StringBuilder();
		for (byte b : Z.getY().toByteArray()) {
			int v = b & 0xFF;
			z_y_Text.append(HEX_ARRAY[v >>> 4]);
			z_y_Text.append(HEX_ARRAY[v & 0x0F]);
		}
		String z_y_Hex = z_y_Text.toString();

		StringBuilder cText = new StringBuilder();
		for (byte b : c) {
			int v = b & 0xFF;
			cText.append(HEX_ARRAY[v >>> 4]);
			cText.append(HEX_ARRAY[v & 0x0F]);
		}
		String cHex = cText.toString();

		// t = KMACXOF256(ka, m, 512, “SKA”)
		byte[] t = KMACXOF256.KMACXOF256_cal(ka, message_b, 512, "PKA".getBytes());

		StringBuilder tText = new StringBuilder();
		for (byte b : t) {
			int v = b & 0xFF;
			tText.append(HEX_ARRAY[v >>> 4]);
			tText.append(HEX_ARRAY[v & 0x0F]);
		}
		String tHex = tText.toString();

		//////////////////////////////////////////////
		///////// Print output to the console ////////
		//////////////////////////////////////////////
		System.out.println("৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩\n");
		System.out.println("Passphrase to generate the key: " + pwd);
		System.out.println("Public Key X: " + KeyX);
		System.out.println("Public Key Y: " + KeyY);
		System.out.println("Message: " + message);
		System.out.println("Cryptogram:");
		System.out.println("Z: (" + z_x_Hex + ", " + z_y_Hex + ")");
		System.out.println("c: " + cHex);
		System.out.println("t: " + tHex);
	}

	/**
	 * Decrypt an elliptic-encrypted text input from a given password
	 * Encrypt/decrypt text input by the user directly to the app instead of having
	 * to be read from a file.
	 * 
	 */
	private static void decryptEllipticInputText() {

		System.out.println("Decrypt an elliptic-encrypted text input from a given password:");

		///////////////////////////////////////////
		/////// Input the cryptogram text /////////
		///// from encryptEllipticInputText() /////
		///////////////////////////////////////////
		System.out.println("This  will use the output from \' 9\' for the inputs.");
		System.out.println("Enter the elliptic encrypted hex string to decrypt.");

		System.out.print("Enter Z.getX(): ");
		String z_x_Hex = input.next();

		System.out.print("Enter Z.getY(): ");
		String z_y_Hex = input.next();

		System.out.print("Enter c_Hex: ");
		String c_Hex = input.next();

		System.out.print("Enter t_Hex: ");
		String t_Hex = input.next();

		String[] encryptHex = new String[] { z_x_Hex, z_y_Hex, c_Hex, t_Hex };

		//////////////////////////////////////////////////////
		/////// Enter the passphrase used to encrypt /////////
		//////////////////////////////////////////////////////

		System.out.println("Please type the passphrase used to encrypt the input text from  9");
		byte[] pw = input.next().getBytes();

		// s = KMACXOF256(pw, “”, 512, “K”); s = 4s
		byte[] byte_s = KMACXOF256.KMACXOF256_cal(pw, "".getBytes(), 512, "K".getBytes());

		byte[] temp = new byte[1];
		temp[0] = (byte) 0x00;
		byte_s = KMACXOF256.concat(temp, byte_s);
		BigInteger s = new BigInteger(byte_s);
		s = s.multiply(new BigInteger("4"));

		// W = s*Z
		EllipticCurve Z = new EllipticCurve(new BigInteger(convertHexToByte(encryptHex[0])),
				new BigInteger(convertHexToByte(encryptHex[1])));
		EllipticCurve W = Z.mulByScalar(s);

		// (ke || ka) = KMACXOF256(Wx, “”, 1024, “P”)
		byte[] keka = KMACXOF256.KMACXOF256_cal(W.getX().toByteArray(), "".getBytes(), 1024, "P".getBytes());
		byte[] ke = Arrays.copyOfRange(keka, 0, 64);
		byte[] ka = Arrays.copyOfRange(keka, 64, keka.length);

		// m = KMACXOF256(ke, “”, |c|, "PKE”) xor c
		byte[] c = convertHexToByte(encryptHex[2]);
		byte[] m = KMACXOF256.KMACXOF256_cal(ke, "".getBytes(), c.length * 8, "PKE".getBytes());
		for (int i = 0; i < m.length; i++) {
			m[i] = (byte) (m[i] ^ c[i]);
		}

		// t’ = KMACXOF256(ka, m, 512, “PKA”)
		byte[] t_prime = KMACXOF256.KMACXOF256_cal(ka, m, 512, "PKA".getBytes());

		System.out.println("৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩\n");
		// accept if, and only if, t’ = t
		if (Arrays.equals(convertHexToByte(encryptHex[3]), t_prime)) {
			System.out.println("Decrypted/Original Text: ");
			System.out.println(new String(m));
		} else {
			System.out.println("Wrong password -> Error decrypting the text!!");
		}
	}

	/**
	 * Sign a given file from a given password and write the signature to a file.
	 * Generating a signature for a byte array m under passphrase pw: s <-
	 * KMACXOF256(pw, “”, 512, “K”); s <- 4s k <- KMACXOF256(s, m, 512, “N”); k <-
	 * 4k U <- k*G; h <- KMACXOF256(Ux, m, 512, “T”); z <- (k – hs) mod r
	 * 
	 */
	private static void signFile() {
		System.out.println("Sign a given file from a given password.\n");
		System.out.println("Please select the file you want to sign");
		byte[] filename = openFile();
		if (filename == null) {
			System.out.println("\nYou did not select any file.\n");
		} else {
			System.out.println("Please enter the passphrase for generating the signature: ");
			byte[] pw = input.next().getBytes();

			// s <- KMACXOF256(pw, “”, 512, “K”); s <- 4s
			// s = KMACXOF256(pw, “”, 512, “K”); s = 4s
			byte[] s_bytes = KMACXOF256.KMACXOF256_cal(pw, "".getBytes(), 512, "K".getBytes());

			byte[] temp = new byte[1];
			temp[0] = (byte) 0x00;

			byte[] s_bytes_pos = KMACXOF256.concat(temp, s_bytes);
			BigInteger s = new BigInteger(s_bytes_pos);
			s = s.multiply(new BigInteger("4"));

			// k <- KMACXOF256(s, m, 512, “N”); k <- 4k
			byte[] k_bytes = KMACXOF256.KMACXOF256_cal(s.toByteArray(), filename, 512, "N".getBytes());
			byte[] k_bytes_pos = KMACXOF256.concat(temp, k_bytes);
			BigInteger k = new BigInteger(k_bytes_pos);
			k = k.multiply(new BigInteger("4"));

			// U < k*G;
			EllipticCurve G = new EllipticCurve(BigInteger.valueOf(4));
			EllipticCurve U = G.mulByScalar(k);

			// h <- KMACXOF256(Ux, m, 512, “T”)
			byte[] h_bytes = KMACXOF256.KMACXOF256_cal(U.getX().toByteArray(), filename, 512, "T".getBytes());
			byte[] h_bytes_pos = KMACXOF256.concat(temp, h_bytes);
			BigInteger h = new BigInteger(h_bytes_pos);
			BigInteger z = k.subtract(h.multiply(s)).mod(EllipticCurve.r);

			// z <- (k – hs) mod r

			String response = saveFile(h.toByteArray(), true);
			System.out.println("৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩\n");
			if (response.equals("")) {
				System.out.println("File could not be written, try again.");
			} else {
				writeToFile(z.toByteArray(), response);
				System.out.println("Signature saved at:  " + response);
			}
		}
	}

	/**
	 * Verify a given data file and its signature file under a given public key
	 * file. Verifying a signature (h, z) for a byte array m under the
	 * (Schnorr/ECDHIES) public key V: U <- z*G + h*V accept if, and only if,
	 * KMACXOF256(Ux, m, 512, “T”) = h
	 * 
	 */
	private static void verifySignature() {
		System.out.println("Verify a given data file and its signature file under a given public key file.\n");
		System.out.println("Please select the input file");
		byte[] filename = openFile();
		if (filename == null) {
			System.out.println("\nYou did not select any file.\n");
		} else {
			System.out.println("Please select the file containing the public key");
			String[] publicKeyString = getLine();
			if (publicKeyString == null) {
				System.out.println("\nYou did not select any file.\n");
			} else {
				System.out.println("Please select the file containing the signature");
				String[] signatureString = getLine();
				if (signatureString == null) {
					System.out.println("\nYou did not select any file.\n");
				} else {

					// U = z*G + h*V
					EllipticCurve V = new EllipticCurve(new BigInteger(convertHexToByte(publicKeyString[0])),
							new BigInteger(convertHexToByte(publicKeyString[1])));
					EllipticCurve G = new EllipticCurve(BigInteger.valueOf(4));
					BigInteger z = new BigInteger(convertHexToByte(signatureString[1]));
					BigInteger h = new BigInteger(convertHexToByte(signatureString[0]));
					EllipticCurve U = G.mulByScalar(z).sum(V.mulByScalar(h));

					byte[] h_bar = KMACXOF256.KMACXOF256_cal(U.getX().toByteArray(), filename, 512, "T".getBytes());
					byte[] temp = new byte[1];
					temp[0] = (byte) 0x00;
					h_bar = KMACXOF256.concat(temp, h_bar);
					System.out.println("৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩৩\n");
					// accept if, and only if, KMACXOF256(Ux, m, 512, “T”) = h
					if (Arrays.equals(convertHexToByte(signatureString[0]), h_bar)) {
						System.out.println(">>>>>>>>>> Signature Verification: SUCCESSFUL!! <<<<<<<<<<");
					} else {
						System.out.println(">>>>>>>>>> Signature Verification: FAILED!! <<<<<<<<<<");
					}
				}
			}
		}
	}

	/////////////////////////////////////////////////////////
	/////////////////// Helper Functions ////////////////////
	/////////////////////////////////////////////////////////

	// As we save the symmetric cryptogram: (z, c, t) -> line by line
	// we have to read the input line by line when decrypt
	private static String[] getLine() {
		FileDialog fd = new FileDialog(new JFrame(), "Open File", FileDialog.LOAD);
		fd.setVisible(true);
		if (fd.getFile() == null) {
			return null;
		} else {
			File file = new File(fd.getDirectory() + fd.getFile());
			try {
				FileInputStream inStream = new FileInputStream(file);
				Scanner lineScan = new Scanner(inStream);
				String[] lines = new String[4];
				int i = 0;
				while (lineScan.hasNextLine()) {
					lines[i++] = lineScan.next();
				}
				inStream.close();
				lineScan.close();
				return lines;
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return null;
	}

	// Use to convert hex string back to byte array to decrypt
	private static byte[] convertHexToByte(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	// Use to write c and t in the same file as z
	private static void writeToFile(byte[] input, String response) {
		File file = new File(response);
		try {
			FileOutputStream output = new FileOutputStream(file, true);
			output.write(System.getProperty("line.separator").getBytes());
			for (byte b : input) {
				String hex = String.format("%02X", b);
				output.write(hex.getBytes());
			}
			output.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	// Use to open the file
	private static byte[] openFile() {
		System.out.println("Open file: ");
		FileDialog fd = new FileDialog(new JFrame(), "Open", FileDialog.LOAD);
		fd.setVisible(true);
		if (fd.getFile() == null) {
			// System.out.print("\nSave file operation was cancelled!! ");
			return null;
		} else {
			File file = new File(fd.getDirectory() + fd.getFile());
			try {
				FileInputStream inStream = new FileInputStream(file);
				byte[] result = inStream.readAllBytes();
				inStream.close();
				return result;
			} catch (IOException e) {
				e.printStackTrace();
			}
			return null;
		}
	}

	// Use to save the output into file
	private static String saveFile(byte[] result, boolean isHex) {
		System.out.println("Save file as: ");
		FileDialog fd = new FileDialog(new JFrame(), "Save as", FileDialog.SAVE);
		fd.setVisible(true);
		if (fd.getFile() == null) {
			System.out.println("\nSave file operation was cancelled!! ");
			return "";
		} else {
			File file = new File(fd.getDirectory() + fd.getFile());
			try {
				FileOutputStream output = new FileOutputStream(file);
				if (isHex) {
					for (byte b : result) {
						String hex = String.format("%02X", b);
						output.write(hex.getBytes());
					}
				} else {
					output.write(result);
				}
				output.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
			return file.getAbsolutePath();
		}
	}
}
