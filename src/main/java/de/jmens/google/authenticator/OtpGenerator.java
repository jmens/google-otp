package de.jmens.google.authenticator;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.stream.IntStream;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base32;

public final class OtpGenerator {

	public static OtpGenerator newOtpGenerator() {
		return new OtpGenerator();
	}

	OtpGenerator() {
		super();
	}

	public boolean verify(String secret, long code) {
		return code == getCode(secret);
	}

	public boolean verify(String secret, long code, long timestamp) {
		return code == getCode(secret, timestamp);
	}

	public boolean verify(String secret, long code, int window) {

		final byte[] decodedSecret = decode(secret);
		final long timestamp = System.currentTimeMillis();

		return IntStream
				.range(0, window)
				.boxed()
				.anyMatch(i ->
						code == getCode(decodedSecret, (timestamp - (i * 1000)))
								|| code == getCode(decodedSecret, (timestamp + (i * 1000)))
				);
	}

	public boolean verify(String secret, long code, long timestamp, int window) {

		final byte[] decodedSecret = decode(secret);

		return IntStream
				.range(0, window)
				.boxed()
				.anyMatch(i ->
						code == getCode(decodedSecret, (timestamp - (i * 1000)))
								|| code == getCode(decodedSecret, (timestamp + (i * 1000)))
				);
	}

	public long getCode(String secret) {
		return getCode(secret, System.currentTimeMillis());
	}

	public long getCode(String secret, long timestamp) {
		return getCode(decode(secret), timestamp);
	}

	private int getCode(byte[] key, long timestamp) {
		final byte[] data = buildData(timestamp / 1000);
		final byte[] hash = hashData(key, data);
		return truncateHash(hash);
	}

	private byte[] buildData(long timestamp) {
		final byte[] data = new byte[8];

		long value = timestamp / 30;
		for (int i = 8; i-- > 0; value >>>= 8) {
			data[i] = (byte) value;
		}
		return data;
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

	private int truncateHash(byte[] hash) {
		final int offset = hash[20 - 1] & 0xF;

		long result = 0;
		for (int i = 0; i < 4; ++i) {
			result <<= 8;
			result |= (hash[offset + i] & 0xFF);
		}

		result &= 0x7FFFFFFF;
		result %= 1000000;

		return (int) result;
	}

	private byte[] decode(String secret) {
		return new Base32().decode(secret);
	}
}
