import java.io.FileInputStream
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.io.IOException
import java.security.KeyStore
import java.security.KeyStore.SecretKeyEntry
import java.security.SecureRandom
import java.security.UnrecoverableKeyException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.system.exitProcess


val aesKey = System.getenv("AES_KEY") ?: null
val aesKeyPassword: CharArray = (System.getenv("AES_KEY_PASSWORD") ?: "changeit").toCharArray()
val keystorePath: String = System.getenv("KEYSTORE_PATH") ?: "keystore.p12"
val keystorePassword: CharArray = (System.getenv("KEYSTORE_PASSWORD") ?: "changeit").toCharArray()
val keystoreType: String = System.getenv("KEYSTORE_TYPE") ?: "PKCS12"
val aesAlgorithm: String = System.getenv("AES_ALGORITHM") ?: "CBC/PKCS5Padding"
val debug: Boolean = (System.getenv("DEBUG") ?: "false").toBoolean()

fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }

fun String.decodeHex(): ByteArray {
    check(length % 2 == 0) { "Must have an even length" }
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

fun eprintln(message: String) {
    System.err.println(message)
}

fun randomSecretKey(): SecretKey {
    val generator = KeyGenerator.getInstance("AES")
    generator.init(256, SecureRandom.getInstanceStrong())
    return generator.generateKey()
}

fun genSecretKeyEntry(key: ByteArray? = null, algo: String = "AES"): SecretKeyEntry {
    val secretKey: SecretKey = if (key != null) {
        SecretKeySpec(key, algo)
    } else {
        eprintln("Generating random AES key")
        randomSecretKey()
    }
//    val secretKey: SecretKey = if (key != null) SecretKeySpec(key, algo) else randomSecretKey()
    return SecretKeyEntry(secretKey)
}

fun genIvParameterSpec(algorithm: String): IvParameterSpec {
    val iv = ByteArray(Cipher.getInstance(algorithm).blockSize)
    SecureRandom.getInstanceStrong().nextBytes(iv)
    return IvParameterSpec(iv)
}

fun encrypt(algorithm: String, rawData: String, key: SecretKey): String {
    val iv: IvParameterSpec = genIvParameterSpec(algorithm)
    val cipher = Cipher.getInstance(algorithm)
    cipher.init(Cipher.ENCRYPT_MODE, key, iv)
    val cipherText = cipher.doFinal(rawData.toByteArray())
    return iv.iv.toHexString() + cipherText.toHexString()
}

fun decrypt(algorithm: String, ciphertext: String, key: SecretKey): String {
    val cipher = Cipher.getInstance(algorithm)
    val ivRaw = ciphertext.slice(0 until ciphertext.length/2).decodeHex()
    val iv = IvParameterSpec(ivRaw)
    val cipherData = ciphertext.slice(ciphertext.length/2 until ciphertext.length).decodeHex()
    cipher.init(Cipher.DECRYPT_MODE, key, iv)
    val data = cipher.doFinal(cipherData)

    return String(data)
}

fun main(args: Array<String>) {
    if (args.size != 1) {
        eprintln("No data to encrypt")
        exitProcess(1)
    }
    val algorithm = "AES/$aesAlgorithm" // Only AES supported
    val rawData: String = args[0] // Data to encrypt
    val keystore: KeyStore = KeyStore.getInstance(keystoreType)
    val aesKeyParams = KeyStore.PasswordProtection(aesKeyPassword)
    val keystoreInputStream: FileInputStream? = try {
        FileInputStream(keystorePath)
    } catch (e: FileNotFoundException) {
        eprintln("Keystore doesn't exist yet, it will be created")
        null
    }

    // Load the keystore from disk, or create an empty one
    try {
        keystore.load(keystoreInputStream, keystorePassword)
    } catch (e: IOException) {
        eprintln("Couldn't load keystore from disk")
        if (e.cause is UnrecoverableKeyException) {
            eprintln("Cause: wrong password")
        }
        exitProcess(1)
    } catch (e: Exception) {
        eprintln("Couldn't load keystore from disk.")
        exitProcess(1)
    } finally {
        keystoreInputStream?.close()
    }

    // Use aes key from env variable if provided, or from keystore
    val keystoreEntry: SecretKeyEntry? = keystore.getEntry("aes_key", aesKeyParams) as? SecretKeyEntry
    val aesKeyByteArray: ByteArray? = if (keystoreEntry != null) {
        eprintln("Using keystore entry")
        keystoreEntry.secretKey?.encoded
    } else if (aesKey != null) {
        eprintln("Using provided key")
        aesKey.decodeHex()
    } else {
        null
    }

    // Build a SecretKeyEntry with the provided AES key or generate a random one
    val secretKeyEntry: SecretKeyEntry = genSecretKeyEntry(aesKeyByteArray, "AES")

    // Add AES key to keystore
    keystore.setEntry("aes_key", secretKeyEntry, aesKeyParams)

    val keystoreOutputStream = FileOutputStream(keystorePath)
    // Save keystore to disk
    try {
        keystore.store(keystoreOutputStream, keystorePassword)
    } catch (e: Exception) {
        eprintln("Couldn't save keystore to disk$e")
        exitProcess(1)
    } finally {
        keystoreOutputStream.close()
    }

    val cipher = encrypt(algorithm, rawData, secretKeyEntry.secretKey)
    println(cipher)

    if (debug) {
        eprintln(secretKeyEntry.secretKey.encoded.toHexString())
        eprintln(decrypt(algorithm, cipher, secretKeyEntry.secretKey))
    }
}
