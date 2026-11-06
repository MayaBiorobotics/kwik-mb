package tech.kwik.agent15.engine.impl;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import tech.kwik.agent15.TlsConstants;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Независимые векторы RFC 8446 §7.5 рассчитаны Python hashlib/hmac, без кода Agent15. */
class TlsExporterTest {
    @Test void exporterMatchesIndependentSha256AndSha384Vectors() throws Exception {
        check("SHA-256", 32, new byte[0], 32, "Ll0qXLT1q+XuwqALQFGt8w19sFNrplIMx8swE82BP3I=");
        check("SHA-256", 32, "context".getBytes(StandardCharsets.US_ASCII), 64, "ClVkv75AIG5poNbgyKy8zCzpXv+llwHTkh8PS7eX9gORqlcQO+gxfhaBY/gV8cpr4dZVJuwvv57o4HiHvagaZQ==");
        check("SHA-384", 48, new byte[0], 64, "Gy4VIYSfxAliqFZBHDI7u5HvUp3/y0mgNAerWKsQG30uceQSrwTTR72HMxCeinKoONsxImG+HZ9RlenXArsdoA==");
    }

    private void check(String algorithm, int size, byte[] context, int length, String expected)
            throws Exception {
        TranscriptHash transcript = mock(TranscriptHash.class);
        when(transcript.getServerHash(TlsConstants.HandshakeType.finished)).thenReturn(
                MessageDigest.getInstance(algorithm).digest(
                        "server-finished-transcript".getBytes(StandardCharsets.US_ASCII)));
        TlsState state = new TlsState(transcript, 16, size);
        assertThrows(IllegalStateException.class,
                () -> state.exportKeyingMaterial("EXPORTER-ErfeData-v1", context, length));
        byte[] handshakeSecret = new byte[size];
        for (int i = 0; i < size; i++) handshakeSecret[i] = (byte) i;
        state.computeApplicationSecrets(handshakeSecret);
        byte[] result = state.exportKeyingMaterial("EXPORTER-ErfeData-v1", context, length);
        assertArrayEquals(Base64.getDecoder().decode(expected), result);
        result[0] ^= 1;
        assertArrayEquals(Base64.getDecoder().decode(expected),
                state.exportKeyingMaterial("EXPORTER-ErfeData-v1", context, length));
        assertThrows(IllegalArgumentException.class,
                () -> state.exportKeyingMaterial("label", context, 255 * size + 1));
        assertThrows(IllegalArgumentException.class,
                () -> state.exportKeyingMaterial("x".repeat(250), context, 32));
    }
}
