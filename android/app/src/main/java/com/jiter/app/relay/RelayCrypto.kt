package com.jiter.app.relay

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Stage 4 Standard Transport Cryptography (Android API 29-35 & JDK 17 native JCA — zero custom crypto):
 *   - ECDHE over NIST P-256 (`secp256r1`) for per-session Perfect Forward Secrecy
 *   - Mutual PSK authentication via HMAC-SHA256 + constant-time `MessageDigest.isEqual`
 *   - RFC 5869 HKDF-SHA256 directional key derivation
 *   - RFC 8439 ChaCha20-Poly1305 AEAD binding the 16-byte WireHeader as AAD
 *   - 64-packet sliding Anti-Replay Window (updated strictly post-AEAD)
 */
object RelayCrypto {
    const val AEAD_TAG_BYTES = 16
    const val P256_UNCOMPRESSED_PUB_BYTES = 65
    const val HANDSHAKE_NONCE_BYTES = 16
    const val HANDSHAKE_TAG_BYTES = 16

    // Exact 26-byte ASN.1 DER SubjectPublicKeyInfo header for EC secp256r1 uncompressed 65B point
    internal val P256_SPKI_PREFIX: ByteArray = byteArrayOf(
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86.toByte(),
        0x48, 0xCE.toByte(), 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
        0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00,
    )

    private val secureRandom = SecureRandom()

    fun derivePskKey(psk: String): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update("jiter-psk-v1:".toByteArray(Charsets.UTF_8))
        md.update(psk.trim().toByteArray(Charsets.UTF_8))
        return md.digest()
    }

    fun randomNonce16(): ByteArray {
        val out = ByteArray(HANDSHAKE_NONCE_BYTES)
        secureRandom.nextBytes(out)
        return out
    }

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    fun hmacSha256(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        for (p in parts) {
            mac.update(p)
        }
        return mac.doFinal()
    }

    fun computeHelloReqTag(
        pskKey: ByteArray,
        sessionId: Int,
        bodyBeforeTag: ByteArray,
    ): ByteArray {
        val sid = ByteArray(4)
        RelayProtocol.putU32(sid, 0, sessionId)
        val full = hmacSha256(
            pskKey,
            "jiter-hello-req-v1".toByteArray(Charsets.UTF_8),
            sid,
            bodyBeforeTag,
        )
        return full.copyOf(HANDSHAKE_TAG_BYTES)
    }

    fun computeHelloAckTag(
        pskKey: ByteArray,
        sessionId: Int,
        clientNonce: ByteArray,
        bodyBeforeTag: ByteArray,
    ): ByteArray {
        val sid = ByteArray(4)
        RelayProtocol.putU32(sid, 0, sessionId)
        val full = hmacSha256(
            pskKey,
            "jiter-hello-ack-v1".toByteArray(Charsets.UTF_8),
            sid,
            clientNonce,
            bodyBeforeTag,
        )
        return full.copyOf(HANDSHAKE_TAG_BYTES)
    }

    /** RFC 5869 HKDF-Extract(salt, IKM) using HMAC-SHA256. */
    fun hkdfExtract(salt: ByteArray?, ikm: ByteArray): ByteArray {
        val actualSalt = if (salt == null || salt.isEmpty()) ByteArray(32) else salt
        return hmacSha256(actualSalt, ikm)
    }

    /** RFC 5869 HKDF-Expand(PRK, info, length) using HMAC-SHA256. */
    fun hkdfExpand(prk: ByteArray, info: ByteArray, outLen: Int): ByteArray {
        require(outLen in 1..(255 * 32)) { "Invalid HKDF outLen: $outLen" }
        val out = ByteArray(outLen)
        var t = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < outLen) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(t)
            mac.update(info)
            mac.update(counter.toByte())
            t = mac.doFinal()
            val take = minOf(t.size, outLen - offset)
            System.arraycopy(t, 0, out, offset, take)
            offset += take
            counter += 1
        }
        return out
    }

    fun deriveSessionKeys(
        ecdhShared: ByteArray,
        pskKey: ByteArray,
        clientNonce: ByteArray,
        serverNonce: ByteArray,
        sessionId: Int,
    ): SessionKeyMaterial {
        require(ecdhShared.size == 32 && pskKey.size == 32)
        require(clientNonce.size == 16 && serverNonce.size == 16)

        val ikm = ByteArray(64)
        System.arraycopy(ecdhShared, 0, ikm, 0, 32)
        System.arraycopy(pskKey, 0, ikm, 32, 32)

        val salt = ByteArray(36)
        System.arraycopy(clientNonce, 0, salt, 0, 16)
        System.arraycopy(serverNonce, 0, salt, 16, 16)
        RelayProtocol.putU32(salt, 32, sessionId)

        val prk = hkdfExtract(salt, ikm)
        return SessionKeyMaterial(
            c2sKey = hkdfExpand(prk, "jiter-v1-c2s-key".toByteArray(Charsets.UTF_8), 32),
            s2cKey = hkdfExpand(prk, "jiter-v1-s2c-key".toByteArray(Charsets.UTF_8), 32),
            c2sIv = hkdfExpand(prk, "jiter-v1-c2s-iv".toByteArray(Charsets.UTF_8), 4),
            s2cIv = hkdfExpand(prk, "jiter-v1-s2c-iv".toByteArray(Charsets.UTF_8), 4),
        )
    }

    internal fun bigIntToFixed32(value: BigInteger): ByteArray {
        val raw = value.toByteArray()
        val out = ByteArray(32)
        when {
            raw.size == 32 -> System.arraycopy(raw, 0, out, 0, 32)
            raw.size == 33 && raw[0] == 0.toByte() -> System.arraycopy(raw, 1, out, 0, 32)
            raw.size < 32 -> System.arraycopy(raw, 0, out, 32 - raw.size, raw.size)
            else -> System.arraycopy(raw, raw.size - 32, out, 0, 32)
        }
        return out
    }
}

class EphemeralP256KeyPair private constructor(
    private val privateKey: PrivateKey,
    val publicUncompressed: ByteArray,
) {
    fun diffieHellman(peerPubUncompressed65: ByteArray): ByteArray? {
        if (peerPubUncompressed65.size != RelayCrypto.P256_UNCOMPRESSED_PUB_BYTES ||
            peerPubUncompressed65[0] != 0x04.toByte()
        ) {
            return null
        }
        return try {
            val spki = ByteArray(RelayCrypto.P256_SPKI_PREFIX.size + peerPubUncompressed65.size)
            System.arraycopy(RelayCrypto.P256_SPKI_PREFIX, 0, spki, 0, RelayCrypto.P256_SPKI_PREFIX.size)
            System.arraycopy(
                peerPubUncompressed65,
                0,
                spki,
                RelayCrypto.P256_SPKI_PREFIX.size,
                peerPubUncompressed65.size,
            )
            val peerPub = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))
            val ka = KeyAgreement.getInstance("ECDH")
            ka.init(privateKey)
            ka.doPhase(peerPub, true)
            val raw = ka.generateSecret()
            if (raw.size == 32) raw else null
        } catch (_: Exception) {
            null
        }
    }

    companion object {
        fun generate(): EphemeralP256KeyPair {
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(ECGenParameterSpec("secp256r1"))
            val kp = kpg.generateKeyPair()
            val pub = kp.public as ECPublicKey
            val x = RelayCrypto.bigIntToFixed32(pub.w.affineX)
            val y = RelayCrypto.bigIntToFixed32(pub.w.affineY)
            val sec1 = ByteArray(RelayCrypto.P256_UNCOMPRESSED_PUB_BYTES)
            sec1[0] = 0x04
            System.arraycopy(x, 0, sec1, 1, 32)
            System.arraycopy(y, 0, sec1, 33, 32)
            return EphemeralP256KeyPair(kp.private, sec1)
        }
    }
}

class SessionKeyMaterial(
    val c2sKey: ByteArray,
    val s2cKey: ByteArray,
    val c2sIv: ByteArray,
    val s2cIv: ByteArray,
)

/**
 * 64-packet sliding Anti-Replay Window (RFC 6479).
 * Matches Rust `relay::crypto::ReplayWindow` using unsigned 32-bit sequence comparison.
 */
class ReplayWindow {
    private var initialized: Boolean = false
    private var highest: Long = 0L
    private var bitmap: Long = 0L

    fun wouldAccept(sequence: Int): Boolean {
        val seq = sequence.toLong() and 0xFFFF_FFFFL
        if (seq == 0L) return false
        if (!initialized) return true
        if (seq > highest) return true
        val diff = highest - seq
        if (diff >= 64L) return false
        return (bitmap and (1L shl diff.toInt())) == 0L
    }

    fun markAccepted(sequence: Int) {
        val seq = sequence.toLong() and 0xFFFF_FFFFL
        if (seq == 0L) return
        if (!initialized) {
            initialized = true
            highest = seq
            bitmap = 1L
            return
        }
        if (seq > highest) {
            val shift = seq - highest
            bitmap = if (shift >= 64L) {
                1L
            } else {
                (bitmap shl shift.toInt()) or 1L
            }
            highest = seq
        } else {
            val diff = highest - seq
            if (diff < 64L) {
                bitmap = bitmap or (1L shl diff.toInt())
            }
        }
    }
}

/**
 * Directional RFC 8439 ChaCha20-Poly1305 AEAD session cipher with Anti-Replay Window.
 */
class SessionCipher private constructor(
    txKeyBytes: ByteArray,
    rxKeyBytes: ByteArray,
    private val txIv: ByteArray,
    private val rxIv: ByteArray,
) {
    private val txKeySpec = SecretKeySpec(txKeyBytes, "ChaCha20")
    private val rxKeySpec = SecretKeySpec(rxKeyBytes, "ChaCha20")
    private val txLock = Any()
    private val rxLock = Any()
    private val replayWindow = ReplayWindow()

    fun encrypt(
        sessionId: Int,
        sequence: Int,
        aadHeader: ByteArray,
        plaintext: ByteArray,
        plainLen: Int = plaintext.size,
    ): ByteArray? = synchronized(txLock) {
        try {
            val nonce = buildNonce(txIv, sessionId, sequence)
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipher.init(Cipher.ENCRYPT_MODE, txKeySpec, IvParameterSpec(nonce))
            cipher.updateAAD(aadHeader)
            cipher.doFinal(plaintext, 0, plainLen)
        } catch (_: Exception) {
            null
        }
    }

    fun decryptAndCheckReplay(
        sessionId: Int,
        sequence: Int,
        aadHeader: ByteArray,
        ciphertext: ByteArray,
        offset: Int = 0,
        length: Int = ciphertext.size - offset,
    ): ByteArray? = synchronized(rxLock) {
        if (length < RelayCrypto.AEAD_TAG_BYTES) return null
        if (!replayWindow.wouldAccept(sequence)) return null
        try {
            val nonce = buildNonce(rxIv, sessionId, sequence)
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipher.init(Cipher.DECRYPT_MODE, rxKeySpec, IvParameterSpec(nonce))
            cipher.updateAAD(aadHeader)
            val plain = cipher.doFinal(ciphertext, offset, length)
            // Update replay window strictly AFTER Poly1305 authentication succeeds
            replayWindow.markAccepted(sequence)
            plain
        } catch (_: Exception) {
            null
        }
    }

    private fun buildNonce(iv: ByteArray, sessionId: Int, sequence: Int): ByteArray {
        val nonce = ByteArray(12)
        System.arraycopy(iv, 0, nonce, 0, 4)
        RelayProtocol.putU32(nonce, 4, sessionId)
        RelayProtocol.putU32(nonce, 8, sequence)
        return nonce
    }

    companion object {
        fun forClient(keys: SessionKeyMaterial): SessionCipher = SessionCipher(
            txKeyBytes = keys.c2sKey,
            rxKeyBytes = keys.s2cKey,
            txIv = keys.c2sIv,
            rxIv = keys.s2cIv,
        )

        fun forServer(keys: SessionKeyMaterial): SessionCipher = SessionCipher(
            txKeyBytes = keys.s2cKey,
            rxKeyBytes = keys.c2sKey,
            txIv = keys.s2cIv,
            rxIv = keys.c2sIv,
        )
    }
}
