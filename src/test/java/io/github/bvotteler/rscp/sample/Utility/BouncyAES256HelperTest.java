package io.github.bvotteler.rscp.sample.Utility;

import io.github.bvotteler.rscp.util.ByteUtils;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertThat;

public class BouncyAES256HelperTest {

    @Test
    public void encryptedAuthFrameIsAsExpected() {
        String password = "top secret";

        AES256Helper aes = BouncyAES256Helper.createBouncyAES256Helper(password);

        // prepared these... basically just to avoid regressions if i fiddle with encrypt/decrypt
        String input = "e3 dc 00 11 51 77 05 58 00 00 00 00 00 66 64 2b 3e 00 01 00 00 00 0e 37 00 02 00 00 00 0d 1e 00 77 6f 6c 66 72 61 6d 2e 76 6f 74 74 65 6c 65 72 40 76 6f 74 74 65 6c 65 72 2e 69 6e 66 6f 03 00 00 00 0d 0b 00 4b 68 61 6e 46 6c 61 73 68 39 35 d9 97 1a eb".replaceAll("\\s+", "");
        String expected = "c1 ac 5d 74 b1 5b 23 85 99 1e 27 0d 29 06 c5 03 e7 ff b9 8e 10 5d 15 6b ea 32 e2 8c 54 a9 3c 50 fc bc a2 4f 57 bf 06 db 5f 6e 2e 29 16 e8 c1 7f af 20 0c f8 db 6b 79 d3 af 66 4c d5 d4 02 86 d7 36 9d c8 3e 81 ae 6b 32 86 2b 19 0c 3d 10 45 8e 2c 42 0d 61 20 d7 96 61 43 5b 9b 05 22 11 87 19".replaceAll("\\s+", "");

        byte[] encrypted = aes.encrypt(ByteUtils.hexStringToByteArray(input));
        String actual = ByteUtils.byteArrayToHexString(encrypted);

        assertThat(actual, is(expected));
    }

    @Test
    public void encryptDecryptRoundtripWorks() {
        AES256Helper aes = BouncyAES256Helper.createBouncyAES256Helper("super secret");
        String input = "e3 dc 00 11 51 77 05 58 00 00 00 00 00 66 64 2b 3e 00 01 00 00 00 0e 37 00 02 00 00 00 0d 1e 00 77 6f 6c 66 72 61 6d 2e 76 6f 74 74 65 6c 65 72 40 76 6f 74 74 65 6c 65 72 2e 69 6e 66 6f 03 00 00 00 0d 0b 00 4b 68 61 6e 46 6c 61 73 68 39 35 d9 97 1a eb".replaceAll("\\s+", "");

        byte[] encrypted = aes.encrypt(ByteUtils.hexStringToByteArray(input));
        byte[] decrypted = aes.decrypt(encrypted);
        String decryptedHex = ByteUtils.byteArrayToHexString(decrypted);

        assertThat(decryptedHex, equalTo(input));
    }

    @Test
    public void encryptDecryptMultipleRoundtripsWork() {
        AES256Helper aes = BouncyAES256Helper.createBouncyAES256Helper("super secret");
        String input = "e3 dc 00 11 51 77 05 58 00 00 00 00 00 66 64 2b 3e 00 01 00 00 00 0e 37 00 02 00 00 00 0d 1e 00 77 6f 6c 66 72 61 6d 2e 76 6f 74 74 65 6c 65 72 40 76 6f 74 74 65 6c 65 72 2e 69 6e 66 6f 03 00 00 00 0d 0b 00 4b 68 61 6e 46 6c 61 73 68 39 35 d9 97 1a eb".replaceAll("\\s+", "");

        byte[] encrypted = aes.encrypt(ByteUtils.hexStringToByteArray(input));
        byte[] decrypted = aes.decrypt(encrypted);

        // looks silly, but helps validate that the initialization vectors are
        // updated correctly for subsequent encrypt/decrypt operations
        for (int i =0; i < 5; i++) {
            encrypted = aes.encrypt(decrypted);
            decrypted = aes.decrypt(encrypted);
        }

        String decryptedHex = ByteUtils.byteArrayToHexString(decrypted);

        assertThat(decryptedHex, equalTo(input));
    }
}
