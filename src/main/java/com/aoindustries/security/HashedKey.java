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
import com.aoindustries.lang.Strings;
import com.aoindustries.lang.SysExits;
import static com.aoindustries.security.HashedPassword.DECODER;
import static com.aoindustries.security.HashedPassword.ENCODER;
import static com.aoindustries.security.HashedPassword.SEPARATOR;
import static com.aoindustries.security.HashedPassword.slowEquals;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.math.BigDecimal;
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
// TODO: ResultSet constructor, that takes multiple columns?  Constant for number of columns
//       Same for prepared statement
//       Implement SQLData, too? (With ServiceLoader?)
// Matches src/main/sql/com/aoindustries/security/HashedKey-type.sql
public class HashedKey implements Comparable<HashedKey>, Serializable {

	/**
	 * Indicates that no key is set.
	 */
	public static final String NO_KEY_VALUE = HashedPassword.NO_PASSWORD_VALUE;

	/**
	 * See <a href="https://docs.oracle.com/en/java/javase/12/docs/specs/security/standard-names.html#messagedigest-algorithms">MessageDigest Algorithms</a>
	 *
	 * @see MessageDigest
	 */
	// Matches src/main/sql/com/aoindustries/security/HashedKey.Algorithm-create.sql
	public enum Algorithm {
		/**
		 * @deprecated  MD5 should not be used for any cryptographic purpose.
		 */
		@Deprecated
		MD5("MD5", 128 / Byte.SIZE, 128 / Byte.SIZE),
		/**
		 * SHA-1 is now considered to have at best 65-bits of collision resistance, if using SHA-1 (which you
		 * shouldn't) its key size is correspondingly limited to 64 bits.  See:
		 * <ul>
		 * <li><a href="https://blog.cloudflare.com/why-its-harder-to-forge-a-sha-1-certificate-than-it-is-to-find-a-sha-1-collision/">Why it’s harder to forge a SHA-1 certificate than it is to find a SHA-1 collision</a></li>
		 * <li><a href="https://marc-stevens.nl/research/papers/PhD%20Thesis%20Marc%20Stevens%20-%20Attacks%20on%20Hash%20Functions%20and%20Applications.pdf">Attacks on Hash Functions and Applications - PhD Thesis Marc Stevens - Attacks on Hash Functions and Applications.pdf</a></li>
		 * </ul>
		 *
		 * @deprecated  SHA-1 should no longer be used for any cryptographic purpose.
		 */
		@Deprecated
		SHA_1(
			"SHA-1",
			64 / 8,
			160 / Byte.SIZE
		),
		/**
		 * @deprecated  Collision resistance of at least 128 bits is required
		 */
		@Deprecated
		SHA_224("SHA-224", 224 / Byte.SIZE),
		SHA_256("SHA-256", 256 / Byte.SIZE) {
			/**
			 * Also allows the full 256-bit key for compatibility with previous versions.
			 */
			@Override
			<E extends Throwable> byte[] validateKey(Function<? super String, E> newThrowable, byte[] key) throws E {
				int expected = getHashBytes(); // Full-length key was used in previous releases
				if(key.length != expected) {
					super.validateKey(newThrowable, key);
				}
				return key;
			}
		},
		SHA_384("SHA-384", 384 / Byte.SIZE),
		SHA_512("SHA-512", 512 / Byte.SIZE),
		/**
		 * @deprecated  Collision resistance of at least 128 bits is required
		 */
		@Deprecated
		SHA_512_224("SHA-512/224", 224 / Byte.SIZE),
		SHA_512_256("SHA-512/256", 256 / Byte.SIZE),
		/**
		 * @deprecated  Collision resistance of at least 128 bits is required
		 */
		@Deprecated
		SHA3_224("SHA3-224", 224 / Byte.SIZE),
		SHA3_256("SHA3-256", 256 / Byte.SIZE),
		SHA3_384("SHA3-384", 384 / Byte.SIZE),
		SHA3_512("SHA3-512", 512 / Byte.SIZE);

		/**
		 * Avoid repetitive allocation.
		 */
		static final Algorithm[] values = values();

		/**
		 * Case-insensitive lookup by algorithm name.
		 *
		 * @return  The algorithm or {@code null} when {@code algorithmName == null}
		 *
		 * @throws  IllegalArgumentException when no enum with the given algorithm name (case-insensitive) is found
		 */
		public static Algorithm findAlgorithm(String algorithmName) throws IllegalArgumentException {
			if(algorithmName == null) return null;
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
			return algorithm;
		}

		private final String algorithmName;
		private final int keyBytes;
		private final int hashBytes;

		private Algorithm(String algorithmName, int keyBytes, int hashBytes) {
			assert algorithmName.indexOf(SEPARATOR) == -1;
			this.algorithmName = algorithmName;
			this.keyBytes = keyBytes;
			this.hashBytes = hashBytes;
		}

		/**
		 * <p>
		 * Uses a default key length that is half the hash length.  This is selected so the likelihood to guess the
		 * original key is equal to the hash's expected collision resistance.
		 * </p>
		 * <p>
		 * <a href="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf">NIST 800-107: 4.1 Hash Function Properties</a>:
		 * </p>
		 * <blockquote>
		 * The expected collision-resistance strength of a hash function is half the length of
		 * the hash value produced by that hash function.
		 * </blockquote>
		 */
		private Algorithm(String algorithmName, int hashBytes) {
			this(algorithmName, hashBytes / 2, hashBytes);
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

		<E extends Throwable> byte[] validateKey(Function<? super String,E> newThrowable, byte[] key) throws E {
			int expected = getKeyBytes();
			if(key.length != expected) {
				throw newThrowable.apply(getAlgorithmName() + ": key length mismatch: expected " + expected + ", got " + key.length);
			}
			return key;
		}

		/**
		 * Generates a random plaintext key of the given number of bytes.
		 */
		byte[] generateKey(int keyBytes) {
			byte[] key = new byte[keyBytes];
			Identifier.secureRandom.nextBytes(key);
			return validateKey(AssertionError::new, key);
		}

		/**
		 * Generates a random plaintext key of {@link #getKeyBytes()} bytes in length.
		 *
		 * @see  #hash(byte[])
		 */
		public byte[] generateKey() {
			return generateKey(getKeyBytes());
		}

		/**
		 * Gets the number of bytes required to store the generated hash.
		 */
		public int getHashBytes() {
			return hashBytes;
		}

		// Matches src/main/sql/com/aoindustries/security/HashedKey.Algorithm.validateHash-function.sql
		<E extends Throwable> byte[] validateHash(Function<? super String,E> newThrowable, byte[] hash) throws E {
			int expected = getHashBytes();
			if(hash.length != expected) {
				throw newThrowable.apply(getAlgorithmName() + ": hash length mismatch: expected " + expected + ", got " + hash.length);
			}
			return hash;
		}

		/**
		 * Hashes the given key.
		 *
		 * @see  #generateKey()
		 */
		public byte[] hash(byte[] key) {
			try {
				return validateHash(
					AssertionError::new,
					MessageDigest.getInstance(getAlgorithmName()).digest(
						validateKey(IllegalArgumentException::new, key)
					)
				);
			} catch(NoSuchAlgorithmException e) {
				throw new WrappedException(e);
			}
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
	// Java 9: SHA3_512 could become the default, although SHA2 might still be best for this application?
	public static final Algorithm RECOMMENDED_ALGORITHM = Algorithm.SHA_512;

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
	 * A singleton that may be used in places where no key is set.
	 */
	public static final HashedKey NO_KEY = new HashedKey();

	/**
	 * Generates a random plaintext key of {@link #HASH_BYTES} bytes in length.
	 *
	 * @see  #hash(byte[])
	 *
	 * @deprecated  This generates a key for {@linkplain Algorithm#SHA_256 the previous default algorithm},
	 *              using the previous default of 256-bit length, please use {@link Algorithm#generateKey()} instead.
	 */
	@Deprecated
	public static byte[] generateKey() {
		return Algorithm.SHA_256.generateKey(HASH_BYTES); // The full 256-bit key for compatibility with previous versions
	}

	/**
	 * Hashes the given key.
	 *
	 * @see  #generateKey()
	 *
	 * @deprecated  This generates a hash for {@linkplain Algorithm#SHA_256 the previous default algorithm},
	 *              please use {@link Algorithm#hash(byte[])} instead.
	 */
	@Deprecated
	public static byte[] hash(byte[] key) {
		return Algorithm.SHA_256.hash(key);
	}

	/**
	 * Parses the result of {@link #toString()}.
	 *
	 * @param hashedKey  when {@code null}, returns {@code null}
	 */
	// Matches src/main/sql/com/aoindustries/security/HashedKey.valueOf-function.sql
	public static HashedKey valueOf(String hashedKey) {
		if(hashedKey == null) {
			return null;
		} else if(NO_KEY_VALUE.equals(hashedKey)) {
			return NO_KEY;
		} else if(hashedKey.length() > 0 && hashedKey.charAt(0) == SEPARATOR) {
			int pos = hashedKey.indexOf(SEPARATOR, 1);
			if(pos == -1) throw new IllegalArgumentException("Second separator (" + SEPARATOR + ") not found");
			Algorithm algorithm = Algorithm.findAlgorithm(hashedKey.substring(1, pos));
			byte[] hash = DECODER.decode(hashedKey.substring(pos + 1));
			return new HashedKey(algorithm, hash);
		} else if(hashedKey.length() == (Algorithm.MD5.getHashBytes() * 2)) {
			@SuppressWarnings("deprecation")
			byte[] hash = Strings.convertByteArrayFromHex(hashedKey.toCharArray());
			assert hash.length == Algorithm.MD5.getHashBytes();
			return new HashedKey(Algorithm.MD5, hash);
		} else {
			byte[] hash = DECODER.decode(hashedKey);
			int hashlen = hash.length;
			if(hashlen == Algorithm.SHA_1.getHashBytes()) {
				return new HashedKey(Algorithm.SHA_1, hash);
			} else if(hashlen == Algorithm.SHA_224.getHashBytes()) {
				return new HashedKey(Algorithm.SHA_224, hash);
			} else if(hashlen == Algorithm.SHA_256.getHashBytes()) {
				return new HashedKey(Algorithm.SHA_256, hash);
			} else if(hashlen == Algorithm.SHA_384.getHashBytes()) {
				return new HashedKey(Algorithm.SHA_384, hash);
			} else if(hashlen == Algorithm.SHA_512.getHashBytes()) {
				return new HashedKey(Algorithm.SHA_512, hash);
			} else {
				throw new IllegalArgumentException("Unable to guess algorithm by hash length: " + hashlen);
			}
		}
	}

	private static final long serialVersionUID = 1L;

	private final Algorithm algorithm;
	private final byte[] hash;

	// Matches src/main/sql/com/aoindustries/security/HashedKey.validate-function.sql
	private <E extends Throwable> void validate(Function<? super String,E> newThrowable) throws E {
		if(algorithm == null) {
			if(hash != null) throw newThrowable.apply("hash must be null when algorithm is null");
		} else {
			if(hash == null) throw newThrowable.apply("hash required when have algorithm");
			algorithm.validateHash(newThrowable, hash);
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
	 *
	 * @throws  IllegalArgumentException  when {@code hash.length != HASH_BYTES}
	 */
	public HashedKey(Algorithm algorithm, byte[] hash) throws IllegalArgumentException {
		this.algorithm = Objects.requireNonNull(algorithm);
		this.hash = Arrays.copyOf(hash, hash.length);
		validate(IllegalArgumentException::new);
	}

	/**
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
	 * Gets the string representation of the hashed key  The format is subject to change
	 * over time, but will maintain backward compatibility.
	 * <p>
	 * Please see {@link #valueOf(java.lang.String)} for the inverse operation.
	 * </p>
	 */
	// Matches src/main/sql/com/aoindustries/security/HashedKey.toString-function.sql
	@Override
	public String toString() {
		if(algorithm == null) {
			assert hash == null;
			return NO_KEY_VALUE;
		} else {
			// MD5 is represented as hex characters of hash only
			if(algorithm == Algorithm.MD5) {
				@SuppressWarnings("deprecation")
				String hex = Strings.convertToHex(hash);
				return hex;
			}
			// These algorithms are base-64 of hash only
			else if(
				algorithm == Algorithm.SHA_1
				|| algorithm == Algorithm.SHA_224
				|| algorithm == Algorithm.SHA_256
				|| algorithm == Algorithm.SHA_384
				|| algorithm == Algorithm.SHA_512
			) {
				return ENCODER.encodeToString(hash);
			}
			// All others use separator and explicitely list the algorithm
			else {
				return SEPARATOR + algorithm.getAlgorithmName()
					+ SEPARATOR + ENCODER.encodeToString(hash);
			}
		}
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
			boolean discardMe =
				algorithm == other.algorithm
				& slowEquals(DUMMY_KEY, DUMMY_KEY);
			assert discardMe == true || discardMe == false : "Suppress unused variable warning";
			return false;
		} else {
			return
				algorithm == other.algorithm
				& slowEquals(hash, other.hash);
		}
	}

	/**
	 * The hash code is just the first 32 bits of the hash.
	 */
	@Override
	public int hashCode() {
		return (hash == null) ? 0 : IoUtils.bufferToInt(hash);
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
			if(diff != 0) return diff;
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
				if(diff != 0) return diff;
			}
			return 0;
		}
	}

	public Algorithm getAlgorithm() {
		return algorithm;
	}

	/**
	 * @return  No defensive copy
	 */
	@SuppressWarnings("ReturnOfCollectionOrArrayField")
	public byte[] getHash() {
		return hash;
	}

	@SuppressWarnings("UseOfSystemOutOrSystemErr")
	public static void main(String... args) {
		boolean benchmark = false;
		boolean help = false;
		for(String arg : args) {
			if("-b".equals(arg) || "--benchamrk".equals(arg)) {
				benchmark = true;
			} else if("-h".equals(arg) || "--help".equals(arg)) {
				help = true;
			} else {
				System.err.println("Unrecognized argument: " + arg);
				help = true;
			}
		}
		if(help) {
			System.err.println("usage: " + HashedKey.class.getName() + " [-b|--benchmark] [-h|--help]");
			System.exit(SysExits.EX_USAGE);
		} else {
			boolean hasFailed = false;
			if(benchmark) {
				// Do ten times, but only report the last pass
				for(int i = 10 ; i > 0; i--) {
					boolean output = (i == 1);
					for(Algorithm algorithm : Algorithm.values) {
						try {
							byte[] key = algorithm.generateKey();
							long startNanos = output ? System.nanoTime() : 0;
							HashedKey hashedKey = new HashedKey(algorithm, algorithm.hash(key));
							long endNanos = output ? System.nanoTime() : 0;
							if(output) {
								System.out.println(ENCODER.encodeToString(key));
								System.out.println(hashedKey);
								long nanos = endNanos - startNanos;
								System.out.println(algorithm.getAlgorithmName() + ": Completed in " + BigDecimal.valueOf(nanos, 3).toPlainString() + " µs");
								System.out.println();
							}
						} catch(Error | RuntimeException e) {
							hasFailed = true;
							if(output) {
								System.out.flush();
								System.err.println(algorithm.getAlgorithmName() + ": " + e.toString());
								System.err.flush();
							}
						}
					}
				}
			} else {
				Algorithm algorithm = RECOMMENDED_ALGORITHM;
				try {
					byte[] key = algorithm.generateKey();
					HashedKey hashedKey = new HashedKey(algorithm, algorithm.hash(key));
					System.out.println(ENCODER.encodeToString(key));
					System.out.println(hashedKey);
				} catch(Error | RuntimeException e) {
					hasFailed = true;
					System.out.flush();
					System.err.println(algorithm.getAlgorithmName() + ": " + e.toString());
					System.err.flush();
				}
			}
			if(hasFailed) System.exit(SysExits.EX_SOFTWARE);
		}
	}
}
