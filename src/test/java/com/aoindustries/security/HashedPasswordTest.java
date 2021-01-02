/*
 * ao-security - Best-practices security made usable.
 * Copyright (C) 2020, 2021  AO Industries, Inc.
 *     support@aoindustries.com
 *     7262 Bull Pen Cir
 *     Mobile, AL 36695
 *
 * This file is part of ao-security.
 *
 * ao-security is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ao-security is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with ao-security.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.aoindustries.security;

import static com.aoindustries.security.Identifier.secureRandom;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigDecimal;
import java.util.logging.Logger;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

/**
 * Tests the Identifier class.
 *
 * @author  AO Industries, Inc.
 */
@SuppressWarnings("deprecation")
public class HashedPasswordTest {

	private static final Logger LOGGER = Logger.getLogger(HashedPasswordTest.class.getName());

	public HashedPasswordTest() {
	}

	@Test
	public void testNoPassword() {
		assertNull(HashedPassword.valueOf(null));
		assertSame(HashedPassword.NO_PASSWORD, HashedPassword.valueOf("*"));
		assertSame(HashedPassword.valueOf("*"), HashedPassword.valueOf("*"));
		assertFalse(HashedPassword.valueOf("*").equals(HashedPassword.valueOf("*")));
		assertFalse(HashedPassword.valueOf("*").matches(""));
		assertNull(HashedPassword.NO_PASSWORD.getAlgorithm());
		assertNull(HashedPassword.NO_PASSWORD.getSalt());
		assertEquals(0, HashedPassword.NO_PASSWORD.getIterations());
		assertNull(HashedPassword.NO_PASSWORD.getHash());
	}

	private static UnprotectedPassword generatePassword() {
		if(secureRandom.nextBoolean()) {
			return new UnprotectedPassword();
		} else {
			return new UnprotectedPassword(() -> {
				int length = 1 + secureRandom.nextInt(19);
				char[] password = new char[length];
				for(int i = 0; i < length ; i++) {
					password[i] = (char)secureRandom.nextInt(secureRandom.nextBoolean() ? 0x80 : 0x10000);
				}
				return password;
			});
		}
	}

	private static void testAlgorithm(HashedPassword.Algorithm algorithm, int saltBytes, int iterations, int hashBytes) throws Exception {
		try (UnprotectedPassword password = generatePassword()) {
			assertNotSame(password.getPassword(), password.getPassword());
			assertEquals(-1, algorithm.getAlgorithmName().indexOf(HashedPassword.SEPARATOR));
			assertTrue(algorithm.getSaltBytes() >= 0);
			byte[] salt = algorithm.generateSalt(saltBytes, Identifier.secureRandom);
			assertSame(salt, algorithm.validateSalt(AssertionError::new, salt));
			assertTrue(algorithm.getMinimumIterations() >= 0);
			assertTrue(algorithm.getMaximumIterations() >= 0);
			assertTrue(algorithm.getMaximumIterations() >= algorithm.getMinimumIterations());
			assertEquals(
				"Both min and max 0 when iteration not supported",
				(algorithm.getMinimumIterations() == 0),
				(algorithm.getMaximumIterations() == 0)
			);
			assertTrue(algorithm.getRecommendedIterations() >= algorithm.getMinimumIterations());
			assertTrue(algorithm.getRecommendedIterations() <= algorithm.getMaximumIterations());
			assertEquals(iterations, algorithm.validateIterations(AssertionError::new, iterations));
			assertTrue(algorithm.getHashBytes() >= 0);
			long startNanos = System.nanoTime();
			byte[] algHash = algorithm.hash(password.clone(), salt, iterations, hashBytes);
			long endNanos = System.nanoTime();
			assertSame(algHash, algorithm.validateHash(AssertionError::new, algHash));
			HashedPassword hashedPassword = new HashedPassword(algorithm, salt, iterations, algHash);
			// Warn if too fast
			long nanos = endNanos - startNanos;
			LOGGER.info(
				algorithm.getAlgorithmName() + ": Completed in "
				+ BigDecimal.valueOf(nanos, 6).toPlainString() + " ms"
			);
			long millis = nanos / 1_000_000;
			if(millis < HashedPassword.SUGGEST_INCREASE_ITERATIONS_MILLIS && iterations != 0) {
				LOGGER.warning(
					algorithm.getAlgorithmName() + ": Password was hashed in under "
					+ HashedPassword.SUGGEST_INCREASE_ITERATIONS_MILLIS
					+ " ms, recommend increasing the value of recommendedIterations (currently "
					+ iterations + ")"
				);
			}
			// toString -> valueOf
			String toString = hashedPassword.toString();
			HashedPassword valueOf = HashedPassword.valueOf(toString);
			assertSame(hashedPassword.getAlgorithm(), valueOf.getAlgorithm());
			assertArrayEquals(hashedPassword.getSalt(), valueOf.getSalt());
			assertEquals(hashedPassword.getIterations(), valueOf.getIterations());
			assertArrayEquals(hashedPassword.getHash(), valueOf.getHash());
			assertEquals(hashedPassword, valueOf);
			assertNotSame(hashedPassword, valueOf);
			// Serializable
			ByteArrayOutputStream bout = new ByteArrayOutputStream();
			try (ObjectOutputStream out = new ObjectOutputStream(bout)) {
				out.writeObject(hashedPassword);
			}
			try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bout.toByteArray()))) {
				HashedPassword serialized = (HashedPassword)in.readObject();
				assertSame(hashedPassword.getAlgorithm(), serialized.getAlgorithm());
				assertArrayEquals(hashedPassword.getSalt(), serialized.getSalt());
				assertEquals(hashedPassword.getIterations(), serialized.getIterations());
				assertArrayEquals(hashedPassword.getHash(), serialized.getHash());
				assertEquals(hashedPassword, serialized);
				assertNotSame(hashedPassword, serialized);
			}
			// Compare to other hash of same password
			HashedPassword otherHashedPassword = new HashedPassword(password.clone(), algorithm);
			if(saltBytes != 0) {
				assertFalse("Salted should have unequal instances", hashedPassword.equals(otherHashedPassword));
			} else {
				assertTrue("Not salted should have equal instances", hashedPassword.equals(otherHashedPassword));
			}
			assertSame(algorithm, hashedPassword.getAlgorithm());
			assertNotSame(algHash, hashedPassword.getHash());
			assertTrue(otherHashedPassword.matches(password.clone()));
			assertFalse(password.isDestroyed());
			password.destroy();
			assertTrue(password.isDestroyed());
		}
	}

	private static void testAlgorithm(HashedPassword.Algorithm algorithm) throws Exception {
		testAlgorithm(
			algorithm, algorithm.getSaltBytes(), algorithm.getRecommendedIterations(), algorithm.getHashBytes()
		);
	}

	@Test
	public void testCRYPT() throws Exception {
		testAlgorithm(HashedPassword.Algorithm.CRYPT);
	}

	@Test
	public void testMD5() throws Exception {
		testAlgorithm(HashedPassword.Algorithm.MD5);
	}

	@Test
	public void testSHA_1() throws Exception {
		testAlgorithm(HashedPassword.Algorithm.SHA_1);
	}

	@Test
	public void testPBKDF2WITHHMACSHA1() throws Exception {
		testAlgorithm(HashedPassword.Algorithm.PBKDF2WITHHMACSHA1);
		// Old defaults
		testAlgorithm(
			HashedPassword.Algorithm.PBKDF2WITHHMACSHA1,
			HashedPassword.SALT_BYTES,
			HashedPassword.RECOMMENDED_ITERATIONS,
			HashedPassword.HASH_BYTES
		);
	}

	@Test
	public void testPBKDF2WITHHMACSHA224() throws Exception {
		testAlgorithm(HashedPassword.Algorithm.PBKDF2WITHHMACSHA224);
	}

	@Test
	public void testPBKDF2WITHHMACSHA256() throws Exception {
		testAlgorithm(HashedPassword.Algorithm.PBKDF2WITHHMACSHA256);
	}

	@Test
	public void testPBKDF2WITHHMACSHA384() throws Exception {
		testAlgorithm(HashedPassword.Algorithm.PBKDF2WITHHMACSHA384);
	}

	@Test
	public void testPBKDF2WITHHMACSHA512() throws Exception {
		testAlgorithm(HashedPassword.Algorithm.PBKDF2WITHHMACSHA512);
	}

	@Test
	@SuppressWarnings("ThrowableResultIgnored")
	public void testDeprecatedCompatibility() {
		final String password = new String(generatePassword().getPassword());
		assertEquals(256 / Byte.SIZE, HashedPassword.SALT_BYTES);
		assertEquals(256 / Byte.SIZE, HashedPassword.HASH_BYTES);
		assertEquals(
			HashedPassword.Algorithm.PBKDF2WITHHMACSHA1.getRecommendedIterations() / 2,
			HashedPassword.RECOMMENDED_ITERATIONS
		);
		byte[] salt = HashedPassword.generateSalt();
		assertEquals(256 / Byte.SIZE, salt.length);
		byte[] hash = HashedPassword.hash(password, salt, HashedPassword.RECOMMENDED_ITERATIONS);
		assertEquals(256 / Byte.SIZE, hash.length);
		HashedPassword hashedPassword = new HashedPassword(salt, HashedPassword.RECOMMENDED_ITERATIONS, hash);
		assertTrue(hashedPassword.matches(password));
		if(!password.isEmpty()) {
			assertFalse(hashedPassword.matches(""));
		}
		assertThrows(
			"invalid new salt bytes on deprecated constructor",
			IllegalArgumentException.class,
			() -> new HashedPassword(
				new byte[HashedPassword.Algorithm.PBKDF2WITHHMACSHA1.getSaltBytes()],
				HashedPassword.RECOMMENDED_ITERATIONS,
				hash
			)
		);
		assertThrows(
			"invalid new hash bytes on deprecated constructor",
			IllegalArgumentException.class,
			() -> new HashedPassword(
				salt,
				HashedPassword.RECOMMENDED_ITERATIONS,
				new byte[HashedPassword.Algorithm.PBKDF2WITHHMACSHA1.getHashBytes()]
			)
		);
		assertThrows(
			"mismatch old and new 1",
			IllegalArgumentException.class,
			() -> new HashedPassword(
				HashedPassword.Algorithm.PBKDF2WITHHMACSHA1,
				new byte[HashedPassword.Algorithm.PBKDF2WITHHMACSHA1.getSaltBytes()],
				HashedPassword.RECOMMENDED_ITERATIONS,
				hash
			)
		);
		assertThrows(
			"mismatch old and new 2",
			IllegalArgumentException.class,
			() -> new HashedPassword(
				HashedPassword.Algorithm.PBKDF2WITHHMACSHA1,
				salt,
				HashedPassword.RECOMMENDED_ITERATIONS,
				new byte[HashedPassword.Algorithm.PBKDF2WITHHMACSHA1.getHashBytes()]
			)
		);
	}

	@Test
	public void testSerializedSingleton() throws Exception {
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		try (ObjectOutputStream out = new ObjectOutputStream(bout)) {
			out.writeObject(HashedPassword.NO_PASSWORD);
		}
		try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bout.toByteArray()))) {
			assertSame(HashedPassword.NO_PASSWORD, in.readObject());
		}
	}
}
