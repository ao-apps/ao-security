/*
 * ao-security - Best-practices security made usable.
 * Copyright (C) 2020  AO Industries, Inc.
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

import com.aoindustries.exception.WrappedException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.NoSuchAlgorithmException;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

/**
 * Tests the Identifier class.
 *
 * @author  AO Industries, Inc.
 */
@SuppressWarnings("deprecation")
public class HashedKeyTest {

	public HashedKeyTest() {
	}

	@Test
	public void testNoKey() {
		assertNull(HashedKey.valueOf(null));
		assertSame(HashedKey.NO_KEY, HashedKey.valueOf("*"));
		assertSame(HashedKey.valueOf("*"), HashedKey.valueOf("*"));
		assertFalse(HashedKey.valueOf("*").equals(HashedKey.valueOf("*")));
		assertNull(HashedKey.NO_KEY.getAlgorithm());
		assertNull(HashedKey.NO_KEY.getHash());
	}

	private static void testAlgorithm(HashedKey.Algorithm algorithm, int keyBytes) throws Exception {
		assertTrue(algorithm.getKeyBytes() >= 0);
		byte[] key = algorithm.generateKey(keyBytes);
		assertSame(key, algorithm.validateKey(AssertionError::new, key));
		assertTrue(algorithm.getHashBytes() >= 0);
		byte[] algHash = algorithm.hash(key);
		assertSame(algHash, algorithm.validateHash(AssertionError::new, algHash));
		HashedKey hashedKey = new HashedKey(algorithm, algHash);
		// toString -> valueOf
		String toString = hashedKey.toString();
		HashedKey valueOf = HashedKey.valueOf(toString);
		assertSame(hashedKey.getAlgorithm(), valueOf.getAlgorithm());
		assertArrayEquals(hashedKey.getHash(), valueOf.getHash());
		assertEquals(hashedKey, valueOf);
		assertNotSame(hashedKey, valueOf);
		// Serializable
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		try (ObjectOutputStream out = new ObjectOutputStream(bout)) {
			out.writeObject(hashedKey);
		}
		try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bout.toByteArray()))) {
			HashedKey serialized = (HashedKey)in.readObject();
			assertSame(hashedKey.getAlgorithm(), serialized.getAlgorithm());
			assertArrayEquals(hashedKey.getHash(), serialized.getHash());
			assertEquals(hashedKey, serialized);
			assertNotSame(hashedKey, serialized);
		}
		// Compare to other instance with different key
		byte[] otherKey = algorithm.generateKey();
		byte[] otherHash = algorithm.hash(otherKey);
		HashedKey otherHashedKey = new HashedKey(algorithm, otherHash);
		assertFalse(hashedKey.equals(otherHashedKey));
		assertSame(algorithm, hashedKey.getAlgorithm());
		assertNotSame(algHash, hashedKey.getHash());
		assertEquals("hash size same, regardless of key size", algorithm.getHashBytes(), hashedKey.getHash().length);
	}

	private static void testAlgorithm(HashedKey.Algorithm algorithm) throws Exception {
		testAlgorithm(algorithm, algorithm.getKeyBytes());
	}

	@Test
	public void testMD5() throws Exception {
		testAlgorithm(HashedKey.Algorithm.MD5);
	}

	@Test
	public void testSHA_1() throws Exception {
		testAlgorithm(HashedKey.Algorithm.SHA_1);
	}

	@Test
	public void testSHA_224() throws Exception {
		testAlgorithm(HashedKey.Algorithm.SHA_224);
	}

	@Test
	public void testSHA_256() throws Exception {
		testAlgorithm(HashedKey.Algorithm.SHA_256);
		testAlgorithm(HashedKey.Algorithm.SHA_256, 256 / Byte.SIZE); // Full-length key was used in previous releases
	}

	@Test
	public void testSHA_384() throws Exception {
		testAlgorithm(HashedKey.Algorithm.SHA_384);
	}

	@Test
	public void testSHA_512() throws Exception {
		testAlgorithm(HashedKey.Algorithm.SHA_512);
	}

	@Test
	public void testSHA_512_224() throws Exception {
		testAlgorithm(HashedKey.Algorithm.SHA_512_224);
	}

	@Test
	public void testSHA_512_256() throws Exception {
		testAlgorithm(HashedKey.Algorithm.SHA_512_256);
	}

	@Test
	// Junit 5: @DisabledOnJre
	public void testSHA3_224() throws Exception {
		try {
			testAlgorithm(HashedKey.Algorithm.SHA3_224);
		} catch(WrappedException e) {
			// Java 9: Algorithm will be required
			Throwable cause = e.getCause();
			if(!(cause instanceof NoSuchAlgorithmException)) throw e;
		}
	}

	@Test
	// Junit 5: @DisabledOnJre
	public void testSHA3_256() throws Exception {
		try {
			testAlgorithm(HashedKey.Algorithm.SHA3_256);
		} catch(WrappedException e) {
			// Java 9: Algorithm will be required
			Throwable cause = e.getCause();
			if(!(cause instanceof NoSuchAlgorithmException)) throw e;
		}
	}

	@Test
	// Junit 5: @DisabledOnJre
	public void testSHA3_384() throws Exception {
		try {
			testAlgorithm(HashedKey.Algorithm.SHA3_384);
		} catch(WrappedException e) {
			// Java 9: Algorithm will be required
			Throwable cause = e.getCause();
			if(!(cause instanceof NoSuchAlgorithmException)) throw e;
		}
	}

	@Test
	// Junit 5: @DisabledOnJre
	public void testSHA3_512() throws Exception {
		try {
			testAlgorithm(HashedKey.Algorithm.SHA3_512);
		} catch(WrappedException e) {
			// Java 9: Algorithm will be required
			Throwable cause = e.getCause();
			if(!(cause instanceof NoSuchAlgorithmException)) throw e;
		}
	}

	@Test
	public void testCompareTo() {
		HashedKey noKey = HashedKey.NO_KEY;
		HashedKey md5 = new HashedKey(HashedKey.Algorithm.MD5, new byte[HashedKey.Algorithm.MD5.getHashBytes()]);
		HashedKey sha1 = new HashedKey(HashedKey.Algorithm.SHA_1, new byte[HashedKey.Algorithm.SHA_1.getHashBytes()]);
		assertEquals(0, noKey.compareTo(noKey));
		assertEquals(0, md5.compareTo(md5));
		assertEquals(0, sha1.compareTo(sha1));
		assertTrue(noKey.compareTo(md5) < 0);
		assertTrue(noKey.compareTo(sha1) < 0);
		assertTrue(md5.compareTo(sha1) < 0);
		assertTrue(sha1.compareTo(md5) > 0);
		assertTrue(sha1.compareTo(noKey) > 0);
		assertTrue(md5.compareTo(noKey) > 0);
	}

	@Test
	public void testDeprecatedCompatibility() {
		assertEquals("SHA-256", HashedKey.ALGORITHM);
		assertEquals(256 / Byte.SIZE, HashedKey.HASH_BYTES);
		byte[] key = HashedKey.generateKey();
		assertEquals(256 / Byte.SIZE, key.length);
		byte[] hash = HashedKey.hash(key);
		assertEquals(256 / Byte.SIZE, hash.length);
		HashedKey hashedKey = new HashedKey(hash);
		assertTrue(hashedKey.equals(new HashedKey(HashedKey.Algorithm.SHA_256, hash)));
		assertFalse(hashedKey.equals(HashedKey.NO_KEY));
		assertFalse(HashedKey.NO_KEY.equals(hashedKey));
	}

	@Test
	public void testSerializedSingleton() throws Exception {
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		try (ObjectOutputStream out = new ObjectOutputStream(bout)) {
			out.writeObject(HashedKey.NO_KEY);
		}
		try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bout.toByteArray()))) {
			assertSame(HashedKey.NO_KEY, in.readObject());
		}
	}
}
