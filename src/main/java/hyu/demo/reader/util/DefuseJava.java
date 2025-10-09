package hyu.demo.reader.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class DefuseJava {
    private static final String CIPHER_ALGO = "AES/GCM/NoPadding";
    private static final String KEY_ALGO = "AES";
    private static final int KEY_SIZE_BYTES = 32; // 256-bit
    private static final int GCM_TAG_LENGTH = 16 * 8; // 128-bit
    private static final int GCM_IV_LENGTH = 16; // 96-bit IV

    private final SecretKey secretKey;

    public DefuseJava(String base64Key) {
        if (base64Key == null || base64Key.length() != 137) {
            throw new IllegalArgumentException("Key must be 137 characters long, got: " +
                    (base64Key == null ? "null" : base64Key.length()));
        }

        try {
            // Decode the Defuse v2 key
            byte[] keyBytes = decodeDefuseV2Key(base64Key);
            if (keyBytes.length != KEY_SIZE_BYTES) {
                throw new IllegalArgumentException("Invalid key length. Expected " + KEY_SIZE_BYTES + " bytes, got " + keyBytes.length);
            }
            this.secretKey = new SecretKeySpec(keyBytes, KEY_ALGO);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid key format", e);
        }
    }

    public DefuseJava(byte[] keyBytes) {
        if (keyBytes.length != KEY_SIZE_BYTES) {
            throw new IllegalArgumentException("Key must be " + KEY_SIZE_BYTES + " bytes");
        }
        this.secretKey = new SecretKeySpec(keyBytes, KEY_ALGO);
    }

    public static String generateKey() {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[KEY_SIZE_BYTES];
        random.nextBytes(key);

        // PHP Defuse v2 uses a specific format with header + base64
        return encodeDefuseV2Key(key);
    }

    private static String encodeDefuseV2Key(byte[] key) {
        // PHP Defuse v2 key format: "def00000" + base64 encoded key (padded to 129 chars)
        String header = "def00000"; // Version header for v2

        // First encode the key normally
        String base64Key = phpBase64Encode(key);

        // Defuse pads the base64 to 129 characters with 'a' characters
        // The actual key is only the first 43-44 chars, the rest is padding
        StringBuilder paddedKey = new StringBuilder(129);
        paddedKey.append(base64Key);

        // Pad with 'a' characters to make it 129 characters total
        while (paddedKey.length() < 129) {
            paddedKey.append('a');
        }

        return header + paddedKey.toString();
    }

    private static byte[] decodeDefuseV2Key(String defuseKey) {
        if (!defuseKey.startsWith("def00000")) {
            throw new IllegalArgumentException("Not a Defuse v2 key");
        }

        // Extract the base64 part (after 8-character header)
        String base64Part = defuseKey.substring(8);

        // The actual base64 key is only the meaningful part before padding
        // Find where the real base64 ends (before the 'a' padding starts)
        int realBase64End = 0;
        for (int i = 0; i < base64Part.length(); i++) {
            char c = base64Part.charAt(i);
            if (c == 'a' && i > 10) { // Padding starts with 'a', but we need at least some real base64
                // Check if this is likely padding by seeing if the rest are 'a's
                boolean allPadding = true;
                for (int j = i; j < base64Part.length(); j++) {
                    if (base64Part.charAt(j) != 'a') {
                        allPadding = false;
                        break;
                    }
                }
                if (allPadding) {
                    realBase64End = i;
                    break;
                }
            }
        }

        // If we didn't find padding, use the whole string (minus any trailing = which shouldn't be there)
        if (realBase64End == 0) {
            realBase64End = base64Part.length();
        }

        String realBase64 = base64Part.substring(0, realBase64End);
        return phpBase64Decode(realBase64);
    }

    public String encrypt(String plaintext) {
        if (plaintext == null) {
            throw new IllegalArgumentException("Plaintext cannot be null");
        }

        try {
            // Generate random IV
            SecureRandom random = new SecureRandom();
            byte[] iv = new byte[GCM_IV_LENGTH];
            random.nextBytes(iv);

            // Initialize cipher
            Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

            // Encrypt
            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] ciphertext = cipher.doFinal(plaintextBytes);

            // Extract auth tag (last 16 bytes)
            byte[] encryptedData = Arrays.copyOf(ciphertext, ciphertext.length - 16);
            byte[] authTag = Arrays.copyOfRange(ciphertext, ciphertext.length - 16, ciphertext.length);

            // Combine IV + encrypted data + auth tag
            byte[] result = new byte[iv.length + encryptedData.length + authTag.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(encryptedData, 0, result, iv.length, encryptedData.length);
            System.arraycopy(authTag, 0, result, iv.length + encryptedData.length, authTag.length);

            // Use Defuse v2 format for encrypted data too
            String base64Encrypted = phpBase64Encode(result);
            return "def50200" + base64Encrypted;

        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String decrypt(String asciiSafe) {
        if (asciiSafe == null) {
            throw new IllegalArgumentException("Ciphertext cannot be null");
        }

        try {
            // Check Defuse v2 format
            if (!asciiSafe.startsWith("def5")) {
                throw new IllegalArgumentException("Not a Defuse v2 encrypted string");
            }

            // Extract the base64 part (after 8-character header)
            String base64Part = asciiSafe.substring(8);
            byte[] data = phpBase64Decode(base64Part);

            if (data.length < GCM_IV_LENGTH + 16) {
                throw new IllegalArgumentException("Ciphertext too short");
            }

            // Extract components
            byte[] iv = Arrays.copyOf(data, GCM_IV_LENGTH);
            byte[] authTag = Arrays.copyOfRange(data, data.length - 16, data.length);
            byte[] encryptedData = Arrays.copyOfRange(data, GCM_IV_LENGTH, data.length - 16);

            // Combine encrypted data + auth tag
            byte[] ciphertext = new byte[encryptedData.length + authTag.length];
            System.arraycopy(encryptedData, 0, ciphertext, 0, encryptedData.length);
            System.arraycopy(authTag, 0, ciphertext, encryptedData.length, authTag.length);

            // Initialize cipher
            Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

            // Decrypt
            byte[] decrypted = cipher.doFinal(ciphertext);
            return new String(decrypted, StandardCharsets.UTF_8);

        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }

    // PHP-style base64 encoding (URL-safe, no padding)
    public static String phpBase64Encode(byte[] data) {
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(data);
        // PHP uses different character mapping
        return encoded.replace('+', '-').replace('/', '_');
    }

    // PHP-style base64 decoding
    public static byte[] phpBase64Decode(String data) {
        // Convert to standard base64
        String standard = data.replace('-', '+').replace('_', '/');

        // Add padding if needed
        int padding = 4 - (standard.length() % 4);
        if (padding != 4) {
            standard += "====".substring(0, padding);
        }

        return Base64.getDecoder().decode(standard);
    }

    // Get the ASCII-safe key string
    public String getKeyString() {
        return encodeDefuseV2Key(secretKey.getEncoded());
    }

    // Example usage and testing
    public static void main(String[] args) {
        try {
            // Generate a new key (137 characters)
            String key = generateKey();
            System.out.println("Generated key (" + key.length() + " chars): " + key);

            // Verify it's 137 characters
            if (key.length() != 137) {
                System.out.println("ERROR: Key is not 137 characters!");
                return;
            }

            // Create instance with the key
            DefuseJava crypto = new DefuseJava(key);

            // Test encryption/decryption
            String original = "Hello, World! This is a test message.";
            System.out.println("Original: " + original);

            String encrypted = crypto.encrypt(original);
            System.out.println("Encrypted (" + encrypted.length() + " chars): " + encrypted);

            String decrypted = crypto.decrypt(encrypted);
            System.out.println("Decrypted: " + decrypted);

            // Verify
            System.out.println("Success: " + original.equals(decrypted));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}