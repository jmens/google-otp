package de.jmens.google.authenticator;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;

class OneTimePassVerifierTest {

	@Test
	public void testVerifier() {
		final long code = 475528;
		final String secret = "U5JRXO44N7RED4YE";
		final long timestamp = 1551803414000l;

		assertThat(
				OneTimePassVerifier
						.newVerifier(secret)
						.forTimestamp(timestamp)
						.checkCode(code),
				is(true)
		);

	}

	@Test
	public void testCodeGenerator() {
		final long code = 475528;
		final String secret = "U5JRXO44N7RED4YE";
		final long timestamp = 1551803414000l;

		assertThat(
				OneTimePassVerifier
						.newVerifier(secret)
						.forTimestamp(timestamp)
						.getCode(),
				is(code)
		);
	}
}
