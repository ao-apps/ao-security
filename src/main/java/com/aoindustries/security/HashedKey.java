/*
 * ao-security - Best-practices security made usable.
 * Copyright (C) 2016, 2017, 2019, 2020  AO Industries, Inc.
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
import com.aoindustries.io.IoUtils;
import static com.aoindustries.security.HashedPassword.DECODER;
import static com.aoindustries.security.HashedPassword.ENCODER;
import static com.aoindustries.security.HashedPassword.SEPARATOR;
import static com.aoindustries.security.HashedPassword.isUrlSafe;
import static com.aoindustries.security.HashedPassword.slowEquals;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Function;

/**
 * A hashed random key.
 *
 * @author  AO Industries, Inc.
 */
// TODO: Tests
// TODO: ResultSet constructor, that takes multiple columns?  Constant for number of columns
//       Same for prepared statement
//       Implement SQLData, too? (With ServiceLoader?)
public class HashedKey implements Comparable<HashedKey>, Serializable {

	/**
	 * Indicates that no key is set.
	 */
	public static final String NO_KEY_VALUE = HashedPassword.NO_PASSWORD_VALUE;
	static {
		assert isUrlSafe(NO_KEY_VALUE);
	}

	/**
	 * See <a href="https://docs.oracle.com/en/java/javase/12/docs/specs/security/standard-names.html#messagedigest-algorithms">MessageDigest Algorithms</a>
	 *
	 * @see MessageDigest
	 */
	public enum Algorithm {
		@Deprecated
		SHA_1("SHA-1", 160 / 8),
		SHA_224("SHA-224", 224 / 8),
		SHA_256("SHA-256", 256 / 8),
		SHA_384("SHA-384", 384 / 8),
		SHA_512_224("SHA-512/224", 224 / 8),
		SHA_512_256("SHA-512/256", 256 / 8),
		SHA3_224("SHA3-224", 224 / 8),
		SHA3_256("SHA3-256", 256 / 8),
		SHA3_384("SHA3-384", 384 / 8),
		SHA3_512("SHA3-512", 512 / 8); // Java 9: This could become the default, although SHA2 might still be best for this application

		/**
		 * Avoid repetitive allocation.
		 */
		static final Algorithm[] values = values();

		private final String algorithmName;
		private final int keyBytes;
		private final int hashBytes;

		private Algorithm(String algorithmName, int keyBytes, int hashBytes) {
			assert isUrlSafe(algorithmName);
			assert algorithmName.indexOf(SEPARATOR) == -1;
			this.algorithmName = algorithmName;
			this.keyBytes = keyBytes;
			this.hashBytes = hashBytes;
		}

		private Algorithm(String algorithmName, int hashBytes) {
			this(algorithmName, hashBytes, hashBytes);
		}

		@Override
		public String toString() {
			return algorithmName;
		}

		/**
		 * Gets the {@link MessageDigest} algorithm name.
		 */
		public String getAlgorithmName() {
			return algorithmName;
		}

		/**
		 * Gets the number of bytes of cryptographically strong random data that must be used with this algorithm.
		 */
		public int getKeyBytes() {
			return keyBytes;
		}

		/**
		 * Gets the number of bytes required to store the generated hash.
		 */
		public int getHashBytes() {
			return hashBytes;
		}

		/**
		 * Gets a {@link MessageDigest} for this algorithm.
		 */
		public MessageDigest getMessageDigest() throws NoSuchAlgorithmException {
			return MessageDigest.getInstance(getAlgorithmName());
		}
	}

	/**
	 * @deprecated  This is the value matching {@linkplain Algorithm#SHA_256 the previous default algorithm},
	 *              please use {@link Algorithm#getAlgorithmName()} instead.
	 */
	@Deprecated
	public static final String ALGORITHM = Algorithm.SHA_256.getAlgorithmName();

	/**
	 * The algorithm recommended for use with new keys.  This may change at any time, but previous algorithms will
	 * remain supported.
	 */
	public static final Algorithm RECOMMENDED_ALGORITHM = Algorithm.SHA_512_256;

	/**
	 * Private dummy key array, used to keep constant time when no key available.
	 * <p>
	 * TODO: In theory, does sharing this array make it likely to be in cache, and thus make it clear which hashes do
	 * not have any key set?  Would it matter if it did?
	 * </p>
	 */
	private static final byte[] DUMMY_KEY = new byte[RECOMMENDED_ALGORITHM.getKeyBytes()];

	/**
	 * The number of bytes in the SHA-256 hash.
	 *
	 * @deprecated  This is the value matching {@linkplain Algorithm#SHA_256 the previous default algorithm},
	 *              please use {@link Algorithm#getHashBytes()} instead.
	 */
	@Deprecated
	public static final int HASH_BYTES = Algorithm.SHA_256.getHashBytes();

	/**
	 * A constant that may be used in places where no key is set.
	 */
	public static final HashedKey NO_KEY = new HashedKey();
	static {
		assert isUrlSafe(NO_KEY.toString());
	}

	/**
	 * Generates a random plaintext key of {@link Algorithm#getKeyBytes()} bytes in length.
	 *
	 * @see  #hash(com.aoindustries.security.HashedKey.Algorithm, byte[])
	 */
	public static byte[] generateKey(Algorithm algorithm) {
		byte[] key = new byte[algorithm.getKeyBytes()];
		Identifier.secureRandom.nextBytes(key);
		return key;
	}

	/**
	 * Generates a random plaintext key of {@link #HASH_BYTES} bytes in length.
	 *
	 * @see  #hash(byte[])
	 *
	 * @deprecated  This generates a key for {@linkplain Algorithm#SHA_256 the previous default algorithm},
	 *              please use {@link #generateKey(com.aoindustries.security.HashedKey.Algorithm)} instead.
	 */
	@Deprecated
	public static byte[] generateKey() {
		return generateKey(Algorithm.SHA_256);
	}

	/**
	 * Hashes the given key.
	 *
	 * @see  #generateKey(com.aoindustries.security.HashedKey.Algorithm)
	 */
	public static byte[] hash(Algorithm algorithm, byte[] key) {
		if(key.length != algorithm.getKeyBytes()) {
			throw new IllegalArgumentException(
				"Invalid key length: expecting " + algorithm.getKeyBytes() + ", got " + key.length
			);
		}
		try {
			byte[] hash = algorithm.getMessageDigest().digest(key);
			assert hash.length == algorithm.getHashBytes();
			return hash;
		} catch(NoSuchAlgorithmException e) {
			throw new WrappedException(e);
		}
	}

	/**
	 * Hashes the given key.
	 *
	 * @see  #generateKey()
	 *
	 * @deprecated  This generates a hash for {@linkplain Algorithm#SHA_256 the previous default algorithm},
	 *              please use {@link #hash(com.aoindustries.security.HashedKey.Algorithm, byte[])} instead.
	 */
	@Deprecated
	public static byte[] hash(byte[] key) {
		return hash(Algorithm.SHA_256, key);
	}

	/**
	 * Parses the result of {@link #toString()}.
	 *
	 * @param hashedKey  when {@code null}, returns {@code null}
	 */
	public static HashedKey valueOf(String hashedKey) {
		if(hashedKey == null) {
			return null;
		} else if(NO_KEY_VALUE.equals(hashedKey)) {
			return NO_KEY;
		} else {
			int pos = hashedKey.indexOf(SEPARATOR);
			if(pos == -1) throw new IllegalArgumentException("Separator (" + SEPARATOR + ") not found");
			String algorithmName = hashedKey.substring(0, pos);
			Algorithm algorithm = null;
			// Search backwards, since higher strength algorithms will be used more
			for(int i = Algorithm.values.length - 1; i >= 0; i--) {
				Algorithm a = Algorithm.values[i];
				if(a.getAlgorithmName().equalsIgnoreCase(algorithmName)) {
					algorithm = a;
					break;
				}
			}
			if(algorithm == null) throw new IllegalArgumentException("Unsupported algorithm: " + algorithmName);
			byte[] hash = DECODER.decode(hashedKey.substring(pos + 1));
			return new HashedKey(algorithm, hash);
		}
	}

	private static final long serialVersionUID = 1L;

	private final Algorithm algorithm;
	private final byte[] hash;

	private <E extends Throwable> void validate(Function<? super String,E> newThrowable) throws E {
		if(algorithm == null) {
			if(hash != null) throw newThrowable.apply("hash must be null when algorithm is null");
		} else {
			if(hash == null) throw newThrowable.apply("hash required when have algorithm");
			if(hash.length != algorithm.getHashBytes()) {
				throw newThrowable.apply(
					"hash length mismatch: expected " + algorithm.getHashBytes() + ", got " + hash.length
				);
			}
		}
	}

	/**
	 * Special singleton for {@link #NO_KEY}.
	 */
	private HashedKey() {
		algorithm = null;
		hash = null;
	}

	/**
	 * @param algorithm  The algorithm previously used to hash the key
	 * @param hash       The provided parameter is zeroed.
	 *
	 * @throws  IllegalArgumentException  when {@code hash.length != HASH_BYTES}
	 */
	public HashedKey(Algorithm algorithm, byte[] hash) throws IllegalArgumentException {
		try {
			this.algorithm = Objects.requireNonNull(algorithm);
			this.hash = Arrays.copyOf(hash, hash.length);
		} finally {
			Arrays.fill(hash, (byte)0);
		}
		validate(IllegalArgumentException::new);
	}

	/**
	 * @param hash  The provided parameter is zeroed.
	 *
	 * @deprecated  This represents a hash using {@linkplain Algorithm#SHA_256 the previous default algorithm},
	 *              please use {@link #HashedKey(com.aoindustries.security.HashedKey.Algorithm, byte[])} instead.
	 */
	@Deprecated
	public HashedKey(byte[] hash) {
		this(Algorithm.SHA_256, hash);
	}

	private void readObject(ObjectInputStream ois) throws ClassNotFoundException, IOException {
		ois.defaultReadObject();
		validate(InvalidObjectException::new);
	}

	private Object readResolve() {
		if(algorithm == null) return NO_KEY;
		return this;
	}

	/**
	 * Gets the string representation of the hashed key, which will only contain
	 * <a href="https://www.ietf.org/rfc/rfc3986.html#section-2.3">the simplest of URL-safe characters</a>.
	 * <p>
	 * Please see {@link #valueOf(java.lang.String)} for the inverse operation.
	 * </p>
	 */
	@Override
	public String toString() {
		String str;
		if(algorithm == null) {
			assert hash == null;
			str = NO_KEY_VALUE;
		} else {
			str = algorithm.name()
				+ SEPARATOR + ENCODER.encodeToString(hash);
		}
		assert isUrlSafe(str);
		return str;
	}

	/**
	 * Checks if equal to another hashed key, always {@code false} when either is {@link #NO_KEY}.
	 * <p>
	 * Performs comparisons in length-constant time.
	 * <a href="https://crackstation.net/hashing-security.htm">https://crackstation.net/hashing-security.htm</a>
	 * </p>
	 */
	@Override
	public boolean equals(Object obj) {
		if(!(obj instanceof HashedKey)) return false;
		HashedKey other = (HashedKey)obj;
		// All done for length-constant time comparisons
		if(algorithm == null | other.algorithm == null) {
			// Perform an equality check with default settings, just to occupy the same amount of time as if had a key
			slowEquals(DUMMY_KEY, DUMMY_KEY);
			return false;
		} else {
			return
				algorithm == other.algorithm
				& slowEquals(hash, ((HashedKey)obj).hash);
		}
	}

	/**
	 * The hash code is just the first 32 bits of the hash.
	 */
	@Override
	public int hashCode() {
		return IoUtils.bufferToInt(hash);
	}

	@Override
	public int compareTo(HashedKey other) {
		// NO_KEY first
		if(algorithm == null) {
			return (other.algorithm == null) ? 0 : -1;
		} else if(other.algorithm == null) {
			return 1;
		} else {
			// TODO: constant time compare here?
			int diff = algorithm.compareTo(other.algorithm);
			if(diff != 0) return 0;
			byte[] h1 = hash;
			byte[] h2 = other.hash;
			int hashBytes = algorithm.getHashBytes();
			assert h1.length == hashBytes;
			assert h2.length == hashBytes;
			for(int i = 0; i < hashBytes; i++) {
				diff = Integer.compare(
					Byte.toUnsignedInt(h1[i]),
					Byte.toUnsignedInt(h2[i])
				);
				// Java 9: int diff = Byte.compareUnsigned(h1[i], h2[i]);
				if(diff != 0) return 0;
			}
			return 0;
		}
	}

	@SuppressWarnings("UseOfSystemOutOrSystemErr")
	public static void main(String... args) {
		Algorithm algorithm = RECOMMENDED_ALGORITHM;
		byte[] key = generateKey(algorithm);
		System.out.println(ENCODER.encodeToString(key));
		System.out.println(new HashedKey(algorithm, hash(algorithm, key)));
	}
}
