import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

public class RSA {
    private static BigInteger n, d, e;
    private static int bitLength;

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter Size: ");
        bitLength = sc.nextInt();

        if (bitLength < 256) {
            System.out.println("n must be greater than or equals 256");
            return;
        }

        generateKeys(); // Generate public/private keys

        System.out.println("\nThe generated public key in plaintext: " + fromBigIntegerToString(e));
        System.out.println("The generated public key in big integer: " + e);
        System.out.println("\nThe generated private key in plaintext: " + fromBigIntegerToString(d));
        System.out.println("The generated private key in big integer: " + d + "\n");

        // Read message
        BufferedReader reader = new BufferedReader(new FileReader("message.txt"));
        String plaintext = reader.readLine().trim();
        reader.close();

        System.out.println("Message in plaintext: " + plaintext);

        BigInteger bPlaintext = fromStringToBigInteger(plaintext);
        System.out.println("Message in big integer: " + bPlaintext);

        // Encrypt
        BigInteger bCiphertext = encrypt(bPlaintext);
        System.out.println("\nEncrypted Cipher in plaintext: " + fromBigIntegerToString(bCiphertext));
        System.out.println("Encrypted Cipher in big integer: " + bCiphertext);

        // Save encrypted
        saveFile("encyptedRSA.txt", bCiphertext.toString());

        // Decrypt
        BigInteger decryptedPlaintext = decrypt(bCiphertext);
        String decryptedMessage = fromBigIntegerToString(decryptedPlaintext);

        System.out.println("\nDecrypted Message in plaintext: " + decryptedMessage);
        System.out.println("Decrypted Message in big integer: " + decryptedPlaintext);

        // Save decrypted
        saveFile("decryptedRSA.txt", decryptedMessage);
    }

    private static void generateKeys() {
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);
        n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        e = BigInteger.valueOf(65537);
        if (!phi.gcd(e).equals(BigInteger.ONE)) {
            e = BigInteger.valueOf(3); // fallback
        }
        d = e.modInverse(phi);
    }

    private static BigInteger encrypt(BigInteger message) {
        return message.modPow(e, n);
    }

    private static BigInteger decrypt(BigInteger cipher) {
        return cipher.modPow(d, n);
    }

    private static BigInteger fromStringToBigInteger(String input) {
        return new BigInteger(input.getBytes());
    }

    private static String fromBigIntegerToString(BigInteger input) {
        return new String(input.toByteArray());
    }

    private static void saveFile(String filename, String content) throws IOException {
        BufferedWriter bw = new BufferedWriter(new FileWriter(filename));
        bw.write(content);
        bw.close();
    }
}
