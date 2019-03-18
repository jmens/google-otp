package de.jmens.google.authenticator;

public class OneTimePassVerifier {

	private static final OtpGenerator algorithm = new OtpGenerator();
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
	private long timestamp = System.currentTimeMillis();
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
		return algorithm.verify(new String(secret), code, timestamp, window);
	}

	public long getCode() {
		return algorithm.getCode(new String(secret), timestamp);
	}
}
