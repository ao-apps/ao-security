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
import com.aoindustries.lang.SysExits;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.math.BigDecimal;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Stream;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * A salted, hashed and key stretched password.
 * <a href="https://crackstation.net/hashing-security.htm">https://crackstation.net/hashing-security.htm</a>
 *
 * @author  AO Industries, Inc.
 */
// TODO: Tests
// TODO: ResultSet constructor, that takes multiple columns?  Constant for number of columns
//       Same for prepared statement
//       Implement SQLData, too? (With ServiceLoader?)
public class HashedPassword implements Serializable {

	/**
	 * Value selected to be distinct from the values used by {@link Base64#getEncoder()},
	 * and is similar to the value used in <code>/etc/shadow</code>
	 */
	static final char SEPARATOR = '$';

	/**
	 * Indicates that no password is set.
	 * <p>
	 * This matches a value often used in <code>/etc/shadow</code> when the user has no password set
	 * (although <code>!</code> is also commonly used for this purpose).
	 * </p>
	 * <p>
	 * This is also used as the value used for
	 * <a href="https://aoindustries.com/aoserv/client/apidocs/com/aoindustries/aoserv/client/schema/AoservProtocol.html#FILTERED">filtered data in the AOServ Protocol</a>.
	 * </p>
	 */
	public static final String NO_PASSWORD_VALUE = "*";

	static final Base64.Decoder DECODER = Base64.getDecoder();
	static final Base64.Encoder ENCODER = Base64.getEncoder().withoutPadding();

	/**
	 * The number of milliseconds under which it will be suggested to recommend iterations from
	 * main method with verbose enabled.
	 */
	private static final long SUGGEST_INCREASE_ITERATIONS_MILLIS = 100; // 1/10th of a second

	/**
	 * @see  SecretKeyFactory
	 */
	// Note: These must be ordered by relative strength, from weakest to strongest for isRehashRecommended() to work
	public enum Algorithm {
		// TODO: Add old UnixCrypt and SHA-1 here for backwards compatibility?  Could then remove other HashedPassword entirely.
		/**
		 * From https://crackstation.net/hashing-security.htm
		 *
		 * @deprecated  This was the previous algorithm used.  Please use {@link #PBKDF2WITHHMACSHA512}, which is the
		 *              current {@link #RECOMMENDED_ALGORITHM}, for new passwords.
		 */
		@Deprecated
		PBKDF2WITHHMACSHA1("PBKDF2WithHmacSHA1", 40000, 256 / 8), // Maybe this could/should be 160 bits to match SHA-1, but we used 256 bits in the previous versions
		PBKDF2WITHHMACSHA224("PBKDF2WithHmacSHA224", 50000, 224 / 8),
		PBKDF2WITHHMACSHA256("PBKDF2WithHmacSHA256", 50000, 256 / 8),
		PBKDF2WITHHMACSHA384("PBKDF2WithHmacSHA384", 37000, 384 / 8),
		PBKDF2WITHHMACSHA512("PBKDF2WithHmacSHA512", 37000, 512 / 8);

		/**
		 * Avoid repetitive allocation.
		 */
		static final Algorithm[] values = values();

		private final String algorithmName;
		private final int saltBytes;
		private final int recommendedIterations;
		private final int hashBytes;

		private Algorithm(String algorithmName, int saltBytes, int recommendedIterations, int hashBytes) {
			assert algorithmName.indexOf(SEPARATOR) == -1;
			this.algorithmName = algorithmName;
			this.saltBytes = saltBytes;
			this.recommendedIterations = recommendedIterations;
			this.hashBytes = hashBytes;
		}

		private Algorithm(String algorithmName, int recommendedIterations, int hashBytes) {
			this(algorithmName, hashBytes, recommendedIterations, hashBytes);
		}

		@Override
		public String toString() {
			return algorithmName;
		}

		/**
		 * Gets the {@link SecretKeyFactory} algorithm name.
		 */
		public String getAlgorithmName() {
			return algorithmName;
		}

		/**
		 * Gets the number of bytes of cryptographically strong random data that must be used with this algorithm.
		 */
		public int getSaltBytes() {
			return saltBytes;
		}

		<E extends Throwable> byte[] validateSalt(Function<? super String,E> newThrowable, byte[] salt) throws E {
			int expected = getSaltBytes();
			if(salt.length != expected) {
				throw newThrowable.apply("salt length mismatch: expected " + expected + ", got " + salt.length);
			}
			return salt;
		}

		/**
		 * Gets the minimum number of iterations allowed or {@code 0} when algorithm is not iterated.
		 */
		public int getMinimumIterations() {
			return 1;
		}

		/**
		 * Gets the maximum number of iterations allowed or {@code 0} when algorithm is not iterated.
		 */
		public int getMaximumIterations() {
			return Integer.MAX_VALUE;
		}

		/**
		 * Gets the recommended number of iterations for typical usage or {@code 0} when algorithm is not iterated.
		 * <p>
		 * We may change this value between releases without notice.
		 * Only use this value for new password hashes.
		 * Always store the iterations with the salt and hash, and use the stored
		 * iterations when checking password matches.
		 * </p>
		 * <p>
		 * It is {@linkplain #isRehashRecommended() recommended to re-hash} a password during login when the recommended
		 * iterations has changed.
		 * </p>
		 * <p>
		 * This value is selected to complete the hashing in around {@value #SUGGEST_INCREASE_ITERATIONS_MILLIS} ms
		 * on commodity PC hardware from around the year 2012.
		 * </p>
		 *
		 * @see  #hash(java.lang.String, com.aoindustries.security.HashedPassword.Algorithm, byte[], int)
		 */
		public int getRecommendedIterations() {
			return recommendedIterations;
		}

		<E extends Throwable> int validateIterations(Function<? super String,E> newThrowable, int iterations) throws E {
			int minimumIterations = getMinimumIterations();
			if(iterations < minimumIterations) {
				throw newThrowable.apply(
					getAlgorithmName() + ": iterations < minimumIterations: "
					+ iterations + " < " + minimumIterations
				);
			}
			int maximumIterations = getMaximumIterations();
			if(iterations > maximumIterations) {
				throw newThrowable.apply(
					getAlgorithmName() + ": iterations > maximumIterations: "
					+ iterations + " < " + maximumIterations
				);
			}
			return iterations;
		}

		/**
		 * Gets the number of bytes required to store the generated hash.
		 */
		public int getHashBytes() {
			return hashBytes;
		}

		<E extends Throwable> byte[] validateHash(Function<? super String,E> newThrowable, byte[] hash) throws E {
			int expected = getHashBytes();
			if(hash.length != expected) {
				throw newThrowable.apply("hash length mismatch: expected " + expected + ", got " + hash.length);
			}
			return hash;
		}

		/**
		 * Gets a {@link SecretKeyFactory} for this algorithm.
		 */
		public SecretKeyFactory getSecretKeyFactory() throws NoSuchAlgorithmException {
			return SecretKeyFactory.getInstance(getAlgorithmName());
		}

		static {
			for(Algorithm algorithm : values) {
				assert algorithm.getMaximumIterations() >= 0;
				assert algorithm.getMinimumIterations() >= 0;
				assert algorithm.getMinimumIterations() <= algorithm.getMaximumIterations();
				assert (algorithm.getMinimumIterations() == 0) == (algorithm.getMaximumIterations() == 0) : "Both min and max 0 when iteration not supported";
				assert algorithm.getRecommendedIterations() >= algorithm.getMinimumIterations();
				assert algorithm.getRecommendedIterations() <= algorithm.getMaximumIterations();
			}
		}
	}

	/**
	 * The algorithm recommended for use with new passwords.  This may change at any time, but previous algorithms will
	 * remain supported.
	 * <p>
	 * It is {@linkplain #isRehashRecommended() recommended to re-hash} a password during login when the recommended
	 * algorithm has changed.
	 * </p>
	 */
	public static final Algorithm RECOMMENDED_ALGORITHM = Algorithm.PBKDF2WITHHMACSHA512;

	/**
	 * Private dummy salt array, used to keep constant time when no salt available.
	 * <p>
	 * TODO: In theory, does sharing this array make it likely to be in cache, and thus make it clear which passwords do
	 * not have any password set?  Would it matter if it did?
	 * </p>
	 */
	private static final byte[] DUMMY_SALT = new byte[RECOMMENDED_ALGORITHM.getSaltBytes()];

	/**
	 * The number of bytes in the random salt.
	 *
	 * @deprecated  This is the value matching {@linkplain Algorithm#PBKDF2WITHHMACSHA1 the previous default algorithm},
	 *              please use {@link Algorithm#getSaltBytes()} instead.
	 */
	@Deprecated
	public static final int SALT_BYTES = Algorithm.PBKDF2WITHHMACSHA1.getSaltBytes();

	/**
	 * The number of bytes in the hash.
	 *
	 * @deprecated  This is the value matching {@linkplain Algorithm#PBKDF2WITHHMACSHA1 the previous default algorithm},
	 *              please use {@link Algorithm#getHashBytes()} instead.
	 */
	@Deprecated
	public static final int HASH_BYTES = Algorithm.PBKDF2WITHHMACSHA1.getHashBytes();

	/**
	 * @deprecated  This is the value matching {@linkplain Algorithm#PBKDF2WITHHMACSHA1 the previous default algorithm},
	 *              please use {@link Algorithm#getRecommendedIterations()} instead.
	 */
	@Deprecated
	public static final int RECOMMENDED_ITERATIONS = Algorithm.PBKDF2WITHHMACSHA1.getRecommendedIterations();

	/**
	 * A singleton that may be used in places where no password is set.
	 */
	public static final HashedPassword NO_PASSWORD = new HashedPassword();

	/**
	 * Generates a random salt of {@link Algorithm#getSaltBytes()} bytes in length.
	 *
	 * @see  #hash(java.lang.String, com.aoindustries.security.HashedPassword.Algorithm, byte[], int)
	 */
	public static byte[] generateSalt(Algorithm algorithm) {
		byte[] salt = new byte[algorithm.getSaltBytes()];
		Identifier.secureRandom.nextBytes(salt);
		return salt;
	}

	/**
	 * Generates a random salt of {@link #SALT_BYTES} bytes in length.
	 *
	 * @see  #hash(java.lang.String, byte[], int)
	 *
	 * @deprecated  This generates a salt for {@linkplain Algorithm#PBKDF2WITHHMACSHA1 the previous default algorithm},
	 *              please use {@link #generateSalt(com.aoindustries.security.HashedPassword.Algorithm)} instead.
	 */
	@Deprecated
	public static byte[] generateSalt() {
		return generateSalt(Algorithm.PBKDF2WITHHMACSHA1);
	}

	/**
	 * Hash the given password
	 *
	 * @see  #generateSalt(com.aoindustries.security.HashedPassword.Algorithm)
	 * @see  Algorithm#getRecommendedIterations()
	 */
	public static byte[] hash(String password, Algorithm algorithm, byte[] salt, int iterations) {
		try {
			char[] chars = password.toCharArray();
			try {
				// See https://crackstation.net/hashing-security.htm
				return algorithm.validateHash(
					AssertionError::new,
					algorithm.getSecretKeyFactory().generateSecret(
						new PBEKeySpec(
							chars,
							algorithm.validateSalt(IllegalArgumentException::new, salt),
							algorithm.validateIterations(IllegalArgumentException::new, iterations),
							algorithm.getHashBytes() * 8
						)
					).getEncoded()
				);
			} finally {
				Arrays.fill(chars, (char)0);
			}
		} catch(InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new WrappedException(e);
		}
	}

	/**
	 * Hash the given password
	 *
	 * @see  #generateSalt()
	 * @see  #RECOMMENDED_ITERATIONS
	 *
	 * @deprecated  This generates a hash for {@linkplain Algorithm#PBKDF2WITHHMACSHA1 the previous default algorithm},
	 *              please use {@link #hash(java.lang.String, com.aoindustries.security.HashedPassword.Algorithm, byte[], int)} instead.
	 */
	@Deprecated
	public static byte[] hash(String password, byte[] salt, int iterations) {
		return hash(password, Algorithm.PBKDF2WITHHMACSHA1, salt, iterations);
	}

	/**
	 * Parses the result of {@link #toString()}.
	 *
	 * @param hashedPassword  when {@code null}, returns {@code null}
	 */
	public static HashedPassword valueOf(String hashedPassword) {
		if(hashedPassword == null) {
			return null;
		} else if(NO_PASSWORD_VALUE.equals(hashedPassword)) {
			return NO_PASSWORD;
		} else {
			int pos1 = hashedPassword.indexOf(SEPARATOR);
			if(pos1 == -1) throw new IllegalArgumentException("First separator (" + SEPARATOR + ") not found");
			String algorithmName = hashedPassword.substring(0, pos1);
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
			int pos2 = hashedPassword.indexOf(SEPARATOR, pos1 + 1);
			if(pos2 == -1) throw new IllegalArgumentException("Second separator (" + SEPARATOR + ") not found");
			byte[] salt = DECODER.decode(hashedPassword.substring(pos1 + 1, pos2));
			int pos3 = hashedPassword.indexOf(SEPARATOR, pos2 + 1);
			if(pos3 == -1) throw new IllegalArgumentException("Third separator (" + SEPARATOR + ") not found");
			byte[] hash = DECODER.decode(hashedPassword.substring(pos3 + 1));
			return new HashedPassword(
				algorithm,
				salt,
				Integer.parseInt(hashedPassword.substring(pos2 + 1, pos3)),
				hash
			);
		}
	}

	private static final long serialVersionUID = 1L;

	private final Algorithm algorithm;
	private final byte[] salt;
	private final int iterations;
	private final byte[] hash;

	private <E extends Throwable> void validate(Function<? super String,E> newThrowable) throws E {
		if(algorithm == null) {
			if(salt != null) throw newThrowable.apply("salt must be null when algorithm is null");
			if(iterations != 0) throw newThrowable.apply("iterations must be 0 when algorithm is null");
			if(hash != null) throw newThrowable.apply("hash must be null when algorithm is null");
		} else {
			if(salt == null) throw newThrowable.apply("salt required when have algorithm");
			algorithm.validateSalt(newThrowable, salt);
			algorithm.validateIterations(newThrowable, iterations);
			if(hash == null) throw newThrowable.apply("hash required when have algorithm");
			algorithm.validateHash(newThrowable, hash);
		}
	}

	/**
	 * Special singleton for {@link #NO_PASSWORD}.
	 */
	private HashedPassword() {
		algorithm = null;
		salt = null;
		iterations = 0;
		hash = null;
		validate(IllegalArgumentException::new);
	}

	/**
	 * @param algorithm   The algorithm previously used to hash the password
	 * @param salt        The provided parameter is zeroed.
	 * @param iterations  The number of has iterations
	 * @param hash        The provided parameter is zeroed.
	 *
	 * @throws  IllegalArgumentException  when {@code salt.length != algorithm.getSaltBytes()}
	 *                                    or {@code hash.length != algorithm.getHashBytes()}
	 *                                    or {@code iterations < algorithm.getMinimumIterations()}
	 *                                    or {@code iterations > algorithm.getMaximumIterations()}
	 */
	public HashedPassword(
		Algorithm algorithm,
		byte[] salt,
		int iterations,
		byte[] hash
	) throws IllegalArgumentException {
		try {
			this.algorithm = Objects.requireNonNull(algorithm);
			this.salt = Arrays.copyOf(salt, salt.length);
			this.iterations = iterations;
			this.hash = Arrays.copyOf(hash, hash.length);
		} finally {
			Arrays.fill(salt, (byte)0);
			Arrays.fill(hash, (byte)0);
		}
		validate(IllegalArgumentException::new);
	}

	/**
	 * @param salt        The provided parameter is zeroed.
	 * @param iterations  The number of has iterations
	 * @param hash        The provided parameter is zeroed.
	 *
	 * @deprecated  This represents a hash using {@linkplain Algorithm#PBKDF2WITHHMACSHA1 the previous default algorithm},
	 *              please use {@link #HashedPassword(com.aoindustries.security.HashedPassword.Algorithm, byte[], int, byte[])} instead.
	 */
	@Deprecated
	public HashedPassword(byte[] salt, int iterations, byte[] hash) {
		this(Algorithm.PBKDF2WITHHMACSHA1, salt, iterations, hash);
	}

	private void readObject(ObjectInputStream ois) throws ClassNotFoundException, IOException {
		ois.defaultReadObject();
		validate(InvalidObjectException::new);
	}

	private Object readResolve() {
		if(algorithm == null) return NO_PASSWORD;
		return this;
	}

	/**
	 * Gets the string representation of the hashed password.  The format is subject to change
	 * over time, but will maintain backward compatibility.
	 * <p>
	 * Please see {@link #valueOf(java.lang.String)} for the inverse operation.
	 * </p>
	 */
	@Override
	public String toString() {
		if(algorithm == null) {
			assert salt == null;
			assert iterations == 0;
			assert hash == null;
			return NO_PASSWORD_VALUE;
		} else {
			assert iterations >= 0;
			return algorithm.getAlgorithmName()
				+ SEPARATOR + ENCODER.encodeToString(salt)
				+ SEPARATOR + iterations
				+ SEPARATOR + ENCODER.encodeToString(hash);
		}
	}

	/**
	 * Checks if this matches the provided password, always {@code false} when is {@link #NO_PASSWORD}.
	 * <p>
	 * Performs comparisons in length-constant time.
	 * <a href="https://crackstation.net/hashing-security.htm">https://crackstation.net/hashing-security.htm</a>
	 * </p>
	 */
	public boolean matches(String password) {
		if(algorithm == null) {
			// Perform a hash with default settings, just to occupy the same amount of time as if had a password
			hash(password, RECOMMENDED_ALGORITHM, DUMMY_SALT, RECOMMENDED_ALGORITHM.getRecommendedIterations());
			return false;
		} else {
			// Hash again with the original salt and iterations
			byte[] newHash = hash(password, algorithm, salt, iterations);
			try {
				return slowEquals(hash, newHash);
			} finally {
				Arrays.fill(newHash, (byte)0);
			}
		}
	}

	/**
	 * Compares two byte arrays in length-constant time. This comparison method
	 * is used so that password hashes cannot be extracted from an on-line 
	 * system using a timing attack and then attacked off-line.
	 * <a href="https://crackstation.net/hashing-security.htm">https://crackstation.net/hashing-security.htm</a>
	 *
	 * @param   a       the first byte array
	 * @param   b       the second byte array 
	 * @return          true if both byte arrays are the same, false if not
	 */
	static boolean slowEquals(byte[] a, byte[] b) {
		int diff = a.length ^ b.length;
		for(int i = 0; i < a.length && i < b.length; i++) {
			diff |= a[i] ^ b[i];
		}
		return diff == 0;
	}

	/**
	 * It is recommended to rehash the password during login when the recommended settings are stronger than the
	 * settings used in the previous hashing.
	 */
	public boolean isRehashRecommended() {
		return
			algorithm != null
			&& (
				algorithm.compareTo(RECOMMENDED_ALGORITHM) < 0
				|| iterations < algorithm.getRecommendedIterations()
			);
	}

	@SuppressWarnings("UseOfSystemOutOrSystemErr")
	public static void main(String... args) {
		List<String> passwords = new ArrayList<>(args.length);
		boolean benchmark = false;
		boolean help = false;
		for(String arg : args) {
			if("-b".equals(arg) || "--benchamrk".equals(arg)) {
				benchmark = true;
			} else if("-h".equals(arg) || "--help".equals(arg)) {
				help = true;
			} else {
				passwords.add(arg);
			}
		}
		if(help) {
			System.err.println("usage: " + HashedPassword.class.getName() + " [-b|--benchmark] [-h|--help] [password...]");
			System.err.println("\tReads from standard input when no password arguments");
			System.exit(SysExits.EX_USAGE);
		} else {
			Stream<String> lines;
			if(passwords.isEmpty()) {
				lines = new BufferedReader(new InputStreamReader(System.in)).lines();
			} else {
				lines = passwords.stream();
			}
			final boolean benchmarkFinal = benchmark;
			final boolean[] warmedUp = {false};
			lines.forEachOrdered(
				password -> {
					if(password.isEmpty()) {
						System.out.println(NO_PASSWORD);
					} else if(benchmarkFinal) {
						// Do ten times, but only report the last pass
						for(int i = warmedUp[0] ? 1 : 10 ; i > 0; i--) {
							boolean output = (i == 1);
							for(Algorithm algorithm : Algorithm.values) {
								try {
									int recommendedIterations = algorithm.getRecommendedIterations();
									long startNanos, endNanos;
									byte[] salt = generateSalt(algorithm);
									startNanos = output ? System.nanoTime() : 0;
									byte[] hash = hash(password, algorithm, salt, recommendedIterations);
									endNanos = output ? System.nanoTime() : 0;
									HashedPassword hashedPassword = new HashedPassword(algorithm, salt, recommendedIterations, hash);
									if(output) {
										System.out.println(hashedPassword);
										long nanos = endNanos - startNanos;
										System.out.println("Completed in " + BigDecimal.valueOf(nanos, 6).toPlainString() + " ms");
										long millis = nanos / 1000000;
										if(millis < SUGGEST_INCREASE_ITERATIONS_MILLIS) {
											System.out.flush();
											System.err.println("Password was hashed in under " + SUGGEST_INCREASE_ITERATIONS_MILLIS + " ms, recommend increasing the value of recommendedIterations (currently " + recommendedIterations + ")");
											System.err.flush();
										}
									}
								} catch(WrappedException e) {
									if(output) {
										System.out.flush();
										System.err.println(algorithm.getAlgorithmName() + ": " + e.toString());
										System.err.flush();
									}
								}
							}
						}
						warmedUp[0] = true;
					} else {
						Algorithm algorithm = RECOMMENDED_ALGORITHM;
						int recommendedIterations = algorithm.getRecommendedIterations();
						byte[] salt = generateSalt(algorithm);
						System.out.println(
							new HashedPassword(
								algorithm,
								salt,
								recommendedIterations,
								hash(password, algorithm, salt, recommendedIterations)
							)
						);
					}
				}
			);
		}
	}
}
