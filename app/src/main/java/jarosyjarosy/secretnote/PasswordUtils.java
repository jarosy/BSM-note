package jarosyjarosy.secretnote;

import org.spongycastle.crypto.PBEParametersGenerator;
import org.spongycastle.crypto.digests.SHA3Digest;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.prng.DigestRandomGenerator;

import java.util.Base64;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;

public class PasswordUtils {

    private static final DigestRandomGenerator generator = new DigestRandomGenerator(new SHA3Digest(512));

    public static String hash(String plainPassword) {
        return hash(plainPassword, salt(128), 512, 101501);
    }

    public static String hash(String plainPassword, byte[] salt) {
        return hash(plainPassword, salt, 512, 101501);
    }


    public static String hash(String plainPassword, byte[] salt, int keyLength, int iterations) {
        if (plainPassword.isEmpty()) {
            throw new IllegalArgumentException("password cannot be empty or null");
        }
        if (keyLength < 0) {
            throw new IllegalArgumentException("the key length must be greater than 0");
        }
        if (iterations <= 0) {
            throw new IllegalArgumentException("the number of iterations must be positive");
        }

        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator();

        generator.init(PBEParametersGenerator.PKCS5PasswordToBytes(
                plainPassword.toCharArray()),
                salt,
                iterations);

        return format("%s|%s",
                encode(salt),
                encode(((KeyParameter) generator.generateDerivedParameters(keyLength)).getKey()));
    }

    public static boolean verify(String plainPassword, String hash) {
        if (plainPassword.isEmpty()) {
            throw new IllegalArgumentException();
        }
        if (hash.isEmpty()) {
            throw new IllegalArgumentException();
        }

        return hash(plainPassword, decode(extractSalt(hash))).equals(hash);

    }

    private static byte[] salt(int count) {
        byte[] salt = new byte[count];
        generator.nextBytes(salt);
        return salt;
    }

    private static String encode(byte[] input) {
        return Base64.getEncoder().encodeToString(input);
    }

    private static byte[] decode(String input) {
        return Base64.getDecoder().decode(input.getBytes(UTF_8));
    }

    private static String extractSalt(String input) {
        return input.substring(0, input.indexOf("|"));
    }
}