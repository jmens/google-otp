package de.jmens.google.authenticator;

import java.util.Random;
import org.apache.commons.codec.binary.Base32;

public class KeyGenerator {

	final static Random random = new Random();
	private static int SIZE = 10;

	public static String generateKey() {
		final byte[] buffer = new byte[SIZE];
		random.nextBytes(buffer);
		return new String(new Base32().encode(buffer));
	}
}
