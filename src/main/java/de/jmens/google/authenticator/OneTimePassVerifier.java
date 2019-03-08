package de.jmens.google.authenticator;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.stream.IntStream;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base32;

public class OneTimePassVerifier {

	public static OneTimePassVerifier newVerifier(String secret) {
		return new OneTimePassVerifier(secret.getBytes());
	}

	public static OneTimePassVerifier newVerifier(byte[] secret) {
		return new OneTimePassVerifier(secret);
	}

	private OneTimePassVerifier(byte[] secret) {
		this.secret = secret;
	}

	private byte[] secret;
	private long timestamp = new Date().getTime();
	private int window = 3;

	public OneTimePassVerifier withTimeWindow(int seconds) {
		this.window = seconds;
		return this;
	}

	public OneTimePassVerifier forTimestamp(long milliseconds) {
		this.timestamp = milliseconds;
		return this;
	}

	public boolean checkCode(long code) {

		final byte[] decodedSecret = new Base32().decode(secret);

		return IntStream
				.range(0, window)
				.boxed()
				.anyMatch(i -> code == getCode(decodedSecret, (timestamp - i)));
	}

	private int getCode(byte[] key, long t) {
		final byte[] data = buildData(t);
		final byte[] hash = hashData(key, data);
		return truncateHash(hash);
	}

	private byte[] hashData(byte[] key, byte[] data) {
		try {
			final SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
			final Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(signKey);

			return mac.doFinal(data);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException("Failed to verify code", e);
		}
	}

	private byte[] buildData(long t) {
		final byte[] data = new byte[8];

		long value = t / 30;
		for (int i = 8; i-- > 0; value >>>= 8) {
			data[i] = (byte) value;
		}
		return data;
	}

	private int truncateHash(byte[] hash) {
		final int offset = hash[20 - 1] & 0xF;

		long result = 0;
		for (int i = 0; i < 4; ++i) {
			result <<= 8;
			result |= (hash[offset + i] & 0xFF);
		}

		result &= 0x7FFFFFFF;
		result %= 1000000;

		return (int)result;
	}

}
