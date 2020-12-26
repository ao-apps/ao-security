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
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Random;
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
// TODO: ResultSet constructor, that takes multiple columns?  Constant for number of columns
//       Same for prepared statement
//       Implement SQLData, too? (With ServiceLoader?)
// Matches src/main/sql/com/aoindustries/security/HashedPassword-type.sql
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
	static final Base64.Encoder ENCODER = Base64.getEncoder();

	/**
	 * The number of milliseconds under which it will be suggested to recommend iterations from
	 * main method with verbose enabled.
	 */
	static final long SUGGEST_INCREASE_ITERATIONS_MILLIS = 100; // 1/10th of a second

	/**
	 * @see  SecretKeyFactory
	 */
	// Note: These must be ordered by relative strength, from weakest to strongest for isRehashRecommended() to work
	// Matches src/main/sql/com/aoindustries/security/HashedPassword.Algorithm-create.sql
	public enum Algorithm {
		/**
		 * @deprecated  {@link UnixCrypt} should not be used for any cryptographic purpose, plus this is barely salted
		 *              and not iterated so is subject to both dictionary and brute-force attacks.
		 */
		@Deprecated
		CRYPT("crypt", 2, 0, 0, 0, 64 / Byte.SIZE) {
			// Matches src/main/sql/com/aoindustries/security/HashedPassword.Algorithm.validateSalt-function.sql
			@Override
			<E extends Throwable> byte[] validateSalt(Function<? super String, E> newThrowable, byte[] salt) throws E {
				super.validateSalt(newThrowable, salt);
				if((salt[0] & 0xf0) != 0) throw new IllegalArgumentException(getAlgorithmName() + ": salt must be twelve bits only");
				return salt;
			}

			/**
			 * {@inheritDoc}
			 * <p>
			 * Clears the high-order four bits since the salt is only twelve bits.
			 * </p>
			 */
			@Override
			byte[] generateSalt(int saltBytes, Random random) {
				if(saltBytes != 2) throw new IllegalArgumentException();
				byte[] salt = new byte[2];
				random.nextBytes(salt);
				salt[0] &= 0x0f;
				return validateSalt(AssertionError::new, salt);
			}

			@Override
			byte[] hash(String password, byte[] salt, int iterations, int hashBytes) {
				if(password == null || password.isEmpty()) throw new IllegalArgumentException("Refusing to hash empty password");
				validateSalt(IllegalArgumentException::new, salt);
				validateIterations(IllegalArgumentException::new, iterations);
				if(hashBytes != Long.BYTES) throw new IllegalArgumentException();
				byte[] hash = new byte[Long.BYTES];
				long rsltblock = UnixCrypt.cryptImpl(
					password,
					  ((salt[0] << Byte.SIZE) & 0x0f00)
					| ( salt[1] & 0xff                )
				);
				// System.out.println("rsltblock = " + rsltblock);
				IoUtils.longToBuffer(rsltblock, hash);
				return validateHash(AssertionError::new, hash);
			}

			// Matches src/main/sql/com/aoindustries/security/HashedPassword.Algorithm.toString-function.sql
			@Override
			String toString(byte[] salt, int iterations, byte[] hash) {
				// System.out.println("salt: " + Strings.convertToHex(salt) + ", hash: " + Strings.convertToHex(hash));
				return new String(new char[] {
					// Salt
					UnixCrypt.itoa64( salt[1]                                ),
					UnixCrypt.itoa64((salt[0] << 2) | ((salt[1] >> 6) & 0x03)),
					// Hash
					UnixCrypt.itoa64( hash[0] >> 2                           ),
					UnixCrypt.itoa64((hash[0] << 4) | ((hash[1] >> 4) & 0x0f)),
					UnixCrypt.itoa64((hash[1] << 2) | ((hash[2] >> 6) & 0x03)),
					UnixCrypt.itoa64( hash[2]                                ),
					UnixCrypt.itoa64( hash[3] >> 2                           ),
					UnixCrypt.itoa64((hash[3] << 4) | ((hash[4] >> 4) & 0x0f)),
					UnixCrypt.itoa64((hash[4] << 2) | ((hash[5] >> 6) & 0x03)),
					UnixCrypt.itoa64( hash[5]                                ),
					UnixCrypt.itoa64( hash[6] >> 2                           ),
					UnixCrypt.itoa64((hash[6] << 4) | ((hash[7] >> 4) & 0x0f)),
					UnixCrypt.itoa64( hash[7] << 2                           )
				});
			}
		},
		/**
		 * @deprecated  MD5 should not be used for any cryptographic purpose, plus this is neither salted nor
		 *              iterated so is subject to both dictionary and brute-force attacks.
		 */
		@Deprecated
		MD5("MD5", 0, 0, 0, 0, 128 / Byte.SIZE) {
			@Override
			byte[] hash(String password, byte[] salt, int iterations, int hashBytes) {
				if(password == null || password.isEmpty()) throw new IllegalArgumentException("Refusing to hash empty password");
				validateSalt(IllegalArgumentException::new, salt);
				validateIterations(IllegalArgumentException::new, iterations);
				if(hashBytes != (128 / Byte.SIZE)) throw new IllegalArgumentException();
				try {
					return validateHash(
						AssertionError::new,
						MessageDigest.getInstance(getAlgorithmName()).digest(
							password.getBytes(StandardCharsets.UTF_8)
						)
					);
				} catch(NoSuchAlgorithmException e) {
					throw new WrappedException(e);
				}
			}

			/**
			 * MD5 is represented as hex characters of hash only.
			 */
			// Matches src/main/sql/com/aoindustries/security/HashedPassword.Algorithm.toString-function.sql
			@Override
			String toString(byte[] salt, int iterations, byte[] hash) {
				return Strings.convertToHex(hash);
			}
		},
		/**
		 * @deprecated  SHA-1 should no longer be used for any cryptographic purpose, plus this is neither salted nor
		 *              iterated so is subject to both dictionary and brute-force attacks.
		 */
		@Deprecated
		SHA_1("SHA-1", 0, 0, 0, 0, 160 / Byte.SIZE) {
			@Override
			byte[] hash(String password, byte[] salt, int iterations, int hashBytes) {
				if(password == null || password.isEmpty()) throw new IllegalArgumentException("Refusing to hash empty password");
				validateSalt(IllegalArgumentException::new, salt);
				validateIterations(IllegalArgumentException::new, iterations);
				if(hashBytes != (160 / Byte.SIZE)) throw new IllegalArgumentException();
				try {
					return validateHash(
						AssertionError::new,
						MessageDigest.getInstance(getAlgorithmName()).digest(
							password.getBytes(StandardCharsets.UTF_8)
						)
					);
				} catch(NoSuchAlgorithmException e) {
					throw new WrappedException(e);
				}
			}

			/**
			 * SHA-1 is base-64 only, to match historical usage.
			 */
			// Matches src/main/sql/com/aoindustries/security/HashedPassword.Algorithm.toString-function.sql
			@Override
			String toString(byte[] salt, int iterations, byte[] hash) {
				return ENCODER.encodeToString(hash);
			}
		},
		/**
		 * From https://crackstation.net/hashing-security.htm
		 *
		 * @deprecated  This was the previous algorithm used.  Please use {@link #PBKDF2WITHHMACSHA512}, which is the
		 *              current {@link #RECOMMENDED_ALGORITHM}, for new passwords.
		 */
		@Deprecated
		PBKDF2WITHHMACSHA1("PBKDF2WithHmacSHA1", 128 / Byte.SIZE, 1, Integer.MAX_VALUE, 85000, 160 / Byte.SIZE) {
			/**
			 * Also allows the 256-bit salt for compatibility with previous versions.
			 */
			// Matches src/main/sql/com/aoindustries/security/HashedPassword.Algorithm.validateSalt-function.sql
			@Override
			<E extends Throwable> byte[] validateSalt(Function<? super String, E> newThrowable, byte[] salt) throws E {
				if(salt.length != SALT_BYTES) {
					super.validateSalt(newThrowable, salt);
				}
				return salt;
			}

			/**
			 * Also allows the 256-bit hash for compatibility with previous versions.
			 */
			@Override
			// Matches src/main/sql/com/aoindustries/security/HashedPassword.Algorithm.validateHash-function.sql
			<E extends Throwable> byte[] validateHash(Function<? super String, E> newThrowable, byte[] hash) throws E {
				if(hash.length != HASH_BYTES) {
					super.validateHash(newThrowable, hash);
				}
				return hash;
			}

			/**
			 * Performs an additional check that (salt, hash) are either the old sizes or the new, but not a mismatched
			 * combination between them.
			 */
			// Matches src/main/sql/com/aoindustries/security/HashedPassword.Algorithm.validate-function.sql
			@Override
			<E extends Throwable> void validate(Function<? super String,E> newThrowable, byte[] salt, int iterations, byte[] hash) throws E {
				super.validate(newThrowable, salt, iterations, hash);
				if((salt.length == SALT_BYTES) != (hash.length == HASH_BYTES)) {
					throw newThrowable.apply(
						getAlgorithmName() + ": salt length and hash length mismatch: expected either the old default lengths ("
						+ SALT_BYTES + ", " + HASH_BYTES + ") or the new lengths ("
						+ getSaltBytes() + ", " + getHashBytes() + "), got (" + salt.length + ", " + hash.length + ")"
					);
				}
			}
		},
		/**
		 * @deprecated  Collision resistance of at least 128 bits is required
		 */
		@Deprecated
		PBKDF2WITHHMACSHA224("PBKDF2WithHmacSHA224", 128 / Byte.SIZE, 1, Integer.MAX_VALUE, 50000, 224 / Byte.SIZE),
		PBKDF2WITHHMACSHA256("PBKDF2WithHmacSHA256", 128 / Byte.SIZE, 1, Integer.MAX_VALUE, 50000, 256 / Byte.SIZE),
		PBKDF2WITHHMACSHA384("PBKDF2WithHmacSHA384", 128 / Byte.SIZE, 1, Integer.MAX_VALUE, 37000, 384 / Byte.SIZE),
		PBKDF2WITHHMACSHA512("PBKDF2WithHmacSHA512", 128 / Byte.SIZE, 1, Integer.MAX_VALUE, 37000, 512 / Byte.SIZE);

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
		private final int saltBytes;
		private final int minimumIterations;
		private final int maximumIterations;
		private final int recommendedIterations;
		private final int hashBytes;

		private Algorithm(String algorithmName, int saltBytes, int minimumIterations, int maximumIterations, int recommendedIterations, int hashBytes) {
			assert algorithmName.indexOf(SEPARATOR) == -1;
			this.algorithmName = algorithmName;
			this.saltBytes = saltBytes;
			this.minimumIterations = minimumIterations;
			this.maximumIterations = maximumIterations;
			this.recommendedIterations = recommendedIterations;
			this.hashBytes = hashBytes;
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

		// Matches src/main/sql/com/aoindustries/security/HashedPassword.Algorithm.validateSalt-function.sql
		<E extends Throwable> byte[] validateSalt(Function<? super String,E> newThrowable, byte[] salt) throws E {
			int expected = getSaltBytes();
			if(salt.length != expected) {
				throw newThrowable.apply(getAlgorithmName() + ": salt length mismatch: expected " + expected + ", got " + salt.length);
			}
			return salt;
		}

		/**
		 * Generates a random salt of the given number of bytes
		 * using the provided {@link Random} source.
		 */
		byte[] generateSalt(int saltBytes, Random random) {
			byte[] salt;
			if(saltBytes == 0) {
				salt = EMPTY_BYTE_ARRAY;
			} else {
				salt = new byte[saltBytes];
				random.nextBytes(salt);
			}
			return validateSalt(AssertionError::new, salt);
		}

		/**
		 * Generates a random salt of {@link #getSaltBytes()} bytes in length
		 * using the provided {@link Random} source.
		 *
		 * @see  HashedPassword#HashedPassword(java.lang.String, java.util.Random)
		 * @see  HashedPassword#HashedPassword(java.lang.String, com.aoindustries.security.HashedPassword.Algorithm, java.util.Random)
		 * @see  HashedPassword#HashedPassword(java.lang.String, com.aoindustries.security.HashedPassword.Algorithm, int, java.util.Random)
		 */
		public byte[] generateSalt(Random random) {
			return generateSalt(getSaltBytes(), random);
		}

		/**
		 * Generates a random salt of {@link #getSaltBytes()} bytes in length
		 * using a default {@link SecureRandom} instance, which is not a
		 * {@linkplain SecureRandom#getInstanceStrong() strong instance} to avoid blocking.
		 *
		 * @see  HashedPassword#HashedPassword(java.lang.String)
		 * @see  HashedPassword#HashedPassword(java.lang.String, com.aoindustries.security.HashedPassword.Algorithm)
		 * @see  HashedPassword#HashedPassword(java.lang.String, com.aoindustries.security.HashedPassword.Algorithm, int)
		 */
		public byte[] generateSalt() {
			return generateSalt(Identifier.secureRandom);
		}

		/**
		 * Gets the toString representation for this algorithm.
		 */
		// Matches src/main/sql/com/aoindustries/security/HashedPassword.Algorithm.toString-function.sql
		String toString(byte[] salt, int iterations, byte[] hash) {
			return SEPARATOR + getAlgorithmName()
				+ SEPARATOR + iterations
				+ SEPARATOR + ENCODER.encodeToString(salt)
				+ SEPARATOR + ENCODER.encodeToString(hash);
		}

		/**
		 * Gets the minimum number of iterations allowed or {@code 0} when algorithm is not iterated.
		 */
		public int getMinimumIterations() {
			return minimumIterations;
		}

		/**
		 * Gets the maximum number of iterations allowed or {@code 0} when algorithm is not iterated.
		 */
		public int getMaximumIterations() {
			return maximumIterations;
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
		 * @see  #hash(java.lang.String, byte[], int)
		 * @see  HashedPassword#HashedPassword(java.lang.String)
		 * @see  HashedPassword#HashedPassword(java.lang.String, java.util.Random)
		 * @see  HashedPassword#HashedPassword(java.lang.String, com.aoindustries.security.HashedPassword.Algorithm)
		 * @see  HashedPassword#HashedPassword(java.lang.String, com.aoindustries.security.HashedPassword.Algorithm, java.util.Random)
		 */
		public int getRecommendedIterations() {
			return recommendedIterations;
		}

		// Matches src/main/sql/com/aoindustries/security/HashedPassword.Algorithm.validateIterations-function.sql
		<E extends Throwable> int validateIterations(Function<? super String,E> newThrowable, int iterations) throws E {
			int _minimumIterations = getMinimumIterations();
			if(iterations < _minimumIterations) {
				throw newThrowable.apply(
					getAlgorithmName() + ": iterations < minimumIterations: "
					+ iterations + " < " + _minimumIterations
				);
			}
			int _maximumIterations = getMaximumIterations();
			if(iterations > _maximumIterations) {
				throw newThrowable.apply(
					getAlgorithmName() + ": iterations > maximumIterations: "
					+ iterations + " < " + _maximumIterations
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

		// Matches src/main/sql/com/aoindustries/security/HashedPassword.Algorithm.validateHash-function.sql
		<E extends Throwable> byte[] validateHash(Function<? super String,E> newThrowable, byte[] hash) throws E {
			int expected = getHashBytes();
			if(hash.length != expected) {
				throw newThrowable.apply(getAlgorithmName() + ": hash length mismatch: expected " + expected + ", got " + hash.length);
			}
			return hash;
		}

		// Matches src/main/sql/com/aoindustries/security/HashedPassword.Algorithm.validate-function.sql
		<E extends Throwable> void validate(Function<? super String,E> newThrowable, byte[] salt, int iterations, byte[] hash) throws E {
			if(salt == null) throw newThrowable.apply("salt required when have algorithm");
			validateSalt(newThrowable, salt);
			validateIterations(newThrowable, iterations);
			if(hash == null) throw newThrowable.apply("hash required when have algorithm");
			validateHash(newThrowable, hash);
		}

		/**
		 * Hash the given password to the given number of bytes.
		 */
		byte[] hash(String password, byte[] salt, int iterations, int hashBytes) {
			if(password == null || password.isEmpty()) throw new IllegalArgumentException("Refusing to hash empty password");
			try {
				char[] chars = password.toCharArray();
				try {
					// See https://crackstation.net/hashing-security.htm
					return validateHash(
						AssertionError::new,
						SecretKeyFactory.getInstance(getAlgorithmName()).generateSecret(
							new PBEKeySpec(
								chars,
								validateSalt(IllegalArgumentException::new, salt),
								validateIterations(IllegalArgumentException::new, iterations),
								hashBytes * Byte.SIZE
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
		 * Hash the given password to {@link #getHashBytes()} bytes.
		 *
		 * @see  #generateSalt()
		 * @see  #getRecommendedIterations()
		 */
		public byte[] hash(String password, byte[] salt, int iterations) {
			return hash(password, salt, iterations, getHashBytes());
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
	public static final int SALT_BYTES = 256 / Byte.SIZE;

	/**
	 * Private dummy hash array, used to keep constant time when no salt available.
	 * <p>
	 * TODO: In theory, does sharing this array make it likely to be in cache, and thus make it clear which passwords do
	 * not have any password set?  Would it matter if it did?
	 * </p>
	 */
	private static final byte[] DUMMY_HASH = new byte[RECOMMENDED_ALGORITHM.getHashBytes()];

	/**
	 * The number of bytes in the hash.
	 *
	 * @deprecated  This is the value matching {@linkplain Algorithm#PBKDF2WITHHMACSHA1 the previous default algorithm},
	 *              please use {@link Algorithm#getHashBytes()} instead.
	 */
	@Deprecated
	public static final int HASH_BYTES = 256 / Byte.SIZE;

	/**
	 * @deprecated  This is the value matching {@linkplain Algorithm#PBKDF2WITHHMACSHA1 the previous default algorithm},
	 *              please use {@link Algorithm#getRecommendedIterations()} instead.
	 */
	@Deprecated
	public static final int RECOMMENDED_ITERATIONS = Algorithm.PBKDF2WITHHMACSHA1.getRecommendedIterations()
		// Half the iterations of the new settings because it performs at half the speed due to the additional hash length (256 bits > 160 bits)
		/ 2;

	/**
	 * A singleton that must be used in places where no password is set.
	 */
	public static final HashedPassword NO_PASSWORD = new HashedPassword();

	/**
	 * Generates a random salt of {@link #SALT_BYTES} bytes in length
	 * using a default {@link SecureRandom} instance, which is not a
	 * {@linkplain SecureRandom#getInstanceStrong() strong instance} to avoid blocking.
	 *
	 * @see  #hash(java.lang.String, byte[], int)
	 *
	 * @deprecated  This generates a salt for {@linkplain Algorithm#PBKDF2WITHHMACSHA1 the previous default algorithm},
	 *              please use {@link Algorithm#generateSalt()}, {@link #HashedPassword(java.lang.String)},
	 *              {@link #HashedPassword(java.lang.String, com.aoindustries.security.HashedPassword.Algorithm)},
	 *              {@link #HashedPassword(java.lang.String, com.aoindustries.security.HashedPassword.Algorithm, int)}
	 *              instead.
	 */
	@Deprecated
	public static byte[] generateSalt() {
		return Algorithm.PBKDF2WITHHMACSHA1.generateSalt(SALT_BYTES, Identifier.secureRandom);
	}

	/**
	 * Hash the given password
	 *
	 * @see  #generateSalt()
	 * @see  #RECOMMENDED_ITERATIONS
	 *
	 * @deprecated  This generates a hash for {@linkplain Algorithm#PBKDF2WITHHMACSHA1 the previous default algorithm},
	 *              please use {@link Algorithm#hash(java.lang.String, byte[], int)},
	 *              {@link #HashedPassword(java.lang.String)},
	 *              {@link #HashedPassword(java.lang.String, com.aoindustries.security.HashedPassword.Algorithm)},
	 *              {@link #HashedPassword(java.lang.String, com.aoindustries.security.HashedPassword.Algorithm, int)}
	 *              instead.
	 */
	@Deprecated
	public static byte[] hash(String password, byte[] salt, int iterations) {
		return Algorithm.PBKDF2WITHHMACSHA1.hash(password, salt, iterations, HASH_BYTES);
	}

	private static final byte[] EMPTY_BYTE_ARRAY = {};

	/**
	 * Parses the result of {@link #toString()}.
	 *
	 * @param hashedPassword  when {@code null}, returns {@code null}
	 */
	// Matches src/main/sql/com/aoindustries/security/HashedPassword.valueOf-function.sql
	public static HashedPassword valueOf(String hashedPassword) {
		if(hashedPassword == null) {
			return null;
		} else if(NO_PASSWORD_VALUE.equals(hashedPassword)) {
			return NO_PASSWORD;
		} else if(hashedPassword.length() > 0 && hashedPassword.charAt(0) == SEPARATOR) {
			int pos1 = hashedPassword.indexOf(SEPARATOR, 1);
			if(pos1 == -1) throw new IllegalArgumentException("Second separator (" + SEPARATOR + ") not found");
			Algorithm algorithm = Algorithm.findAlgorithm(hashedPassword.substring(1, pos1));
			int pos2 = hashedPassword.indexOf(SEPARATOR, pos1 + 1);
			if(pos2 == -1) throw new IllegalArgumentException("Third separator (" + SEPARATOR + ") not found");
			int pos3 = hashedPassword.indexOf(SEPARATOR, pos2 + 1);
			if(pos3 == -1) throw new IllegalArgumentException("Fourth separator (" + SEPARATOR + ") not found");
			byte[] salt = DECODER.decode(hashedPassword.substring(pos2 + 1, pos3));
			byte[] hash = DECODER.decode(hashedPassword.substring(pos3 + 1));
			return new HashedPassword(
				algorithm,
				salt,
				Integer.parseInt(hashedPassword.substring(pos1 + 1, pos2)),
				hash
			);
		} else if(hashedPassword.length() == 13) {
			@SuppressWarnings("deprecation")
			int salt =
				  (UnixCrypt.a64toi(hashedPassword.charAt( 1)) << 6)
				|  UnixCrypt.a64toi(hashedPassword.charAt( 0));
			@SuppressWarnings("deprecation")
			long rsltblock =
				  ((long)UnixCrypt.a64toi(hashedPassword.charAt( 2)) << 58)
				| ((long)UnixCrypt.a64toi(hashedPassword.charAt( 3)) << 52)
				| ((long)UnixCrypt.a64toi(hashedPassword.charAt( 4)) << 46)
				| ((long)UnixCrypt.a64toi(hashedPassword.charAt( 5)) << 40)
				| ((long)UnixCrypt.a64toi(hashedPassword.charAt( 6)) << 34)
				| ((long)UnixCrypt.a64toi(hashedPassword.charAt( 7)) << 28)
				| ((long)UnixCrypt.a64toi(hashedPassword.charAt( 8)) << 22)
				| ((long)UnixCrypt.a64toi(hashedPassword.charAt( 9)) << 16)
				| ((long)UnixCrypt.a64toi(hashedPassword.charAt(10)) << 10)
				| ((long)UnixCrypt.a64toi(hashedPassword.charAt(11)) <<  4)
				| ((long)UnixCrypt.a64toi(hashedPassword.charAt(12)) >>  2);
			// System.out.println("rsltblock = " + rsltblock);
			byte[] hash = new byte[Long.BYTES];
			IoUtils.longToBuffer(rsltblock, hash);
			HashedPassword result = new HashedPassword(
				Algorithm.CRYPT,
				new byte[] {
					(byte)((salt >>> Byte.SIZE) & 0x0f),
					(byte)  salt
				},
				0,
				hash
			);
			assert hashedPassword.equals(result.toString());
			return result;
		} else if(hashedPassword.length() == (Algorithm.MD5.getHashBytes() * 2)) {
			@SuppressWarnings("deprecation")
			byte[] hash = Strings.convertByteArrayFromHex(hashedPassword.toCharArray());
			assert hash.length == Algorithm.MD5.getHashBytes();
			return new HashedPassword(Algorithm.MD5, EMPTY_BYTE_ARRAY, 0, hash);
		} else {
			byte[] hash = DECODER.decode(hashedPassword);
			int hashlen = hash.length;
			if(hashlen == Algorithm.SHA_1.getHashBytes()) {
				return new HashedPassword(Algorithm.SHA_1, EMPTY_BYTE_ARRAY, 0, hash);
			} else {
				throw new IllegalArgumentException("Unable to guess algorithm by hash length: " + hashlen);
			}
		}
	}

	/**
	 * Restores a {@link HashedPassword} from its individual fields.  This is useful for reading the object from a
	 * database, for example.
	 *
	 * @param algorithm   The algorithm previously used to hash the password
	 * @param iterations  The number of has iterations
	 *
	 * @throws  IllegalArgumentException  when {@code salt.length != algorithm.getSaltBytes()}
	 *                                    or {@code hash.length != algorithm.getHashBytes()}
	 *                                    or {@code iterations < algorithm.getMinimumIterations()}
	 *                                    or {@code iterations > algorithm.getMaximumIterations()}
	 */
	public static HashedPassword valueOf(
		Algorithm algorithm,
		byte[] salt,
		int iterations,
		byte[] hash
	) throws IllegalArgumentException {
		if(algorithm == null) {
			if(salt != null) throw new IllegalArgumentException("salt must be null when algorithm is null");
			if(iterations != 0) throw new IllegalArgumentException("iterations must be 0 when algorithm is null");
			if(hash != null) throw new IllegalArgumentException("hash must be null when algorithm is null");
			return NO_PASSWORD;
		} else {
			return new HashedPassword(algorithm, salt, iterations, hash);
		}
	}

	private static final long serialVersionUID = 1L;

	private final Algorithm algorithm;
	private final byte[] salt;
	private final int iterations;
	private final byte[] hash;

	// Matches src/main/sql/com/aoindustries/security/HashedPassword.validate-function.sql
	private <E extends Throwable> void validate(Function<? super String,E> newThrowable) throws E {
		if(algorithm == null) {
			if(salt != null) throw newThrowable.apply("salt must be null when algorithm is null");
			if(iterations != 0) throw newThrowable.apply("iterations must be 0 when algorithm is null");
			if(hash != null) throw newThrowable.apply("hash must be null when algorithm is null");
		} else {
			algorithm.validate(newThrowable, salt, iterations, hash);
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
	 * @param iterations  The number of has iterations
	 *
	 * @throws  IllegalArgumentException  when {@code salt.length != algorithm.getSaltBytes()}
	 *                                    or {@code hash.length != algorithm.getHashBytes()}
	 *                                    or {@code iterations < algorithm.getMinimumIterations()}
	 *                                    or {@code iterations > algorithm.getMaximumIterations()}
	 *
	 * @deprecated  Please use {@link #valueOf(com.aoindustries.security.HashedPassword.Algorithm, byte[], int, byte[])},
	 *              which is able to automatically return the {@link #NO_PASSWORD} singleton.
	 */
	@Deprecated
	public HashedPassword(Algorithm algorithm, byte[] salt, int iterations, byte[] hash) throws IllegalArgumentException {
		this.algorithm = Objects.requireNonNull(algorithm);
		this.salt = Arrays.copyOf(salt, salt.length);
		this.iterations = iterations;
		this.hash = Arrays.copyOf(hash, hash.length);
		validate(IllegalArgumentException::new);
	}

	/**
	 * @param iterations  The number of has iterations
	 *
	 * @throws  IllegalArgumentException  when {@code salt.length != SALT_BYTES}
	 *                                    or {@code hash.length != HASH_BYTES}
	 *                                    or {@code iterations < algorithm.getMinimumIterations()}
	 *                                    or {@code iterations > algorithm.getMaximumIterations()}
	 *
	 * @deprecated  This represents a hash using {@linkplain Algorithm#PBKDF2WITHHMACSHA1 the previous default algorithm},
	 *              please use {@link #HashedPassword(java.lang.String)},
	 *              {@link #HashedPassword(java.lang.String, com.aoindustries.security.HashedPassword.Algorithm)},
	 *              or {@link #HashedPassword(java.lang.String, com.aoindustries.security.HashedPassword.Algorithm, int)}
	 *              instead.
	 */
	@Deprecated
	public HashedPassword(byte[] salt, int iterations, byte[] hash) throws IllegalArgumentException {
		this(Algorithm.PBKDF2WITHHMACSHA1, salt, iterations, hash);
		if(salt.length != SALT_BYTES) {
			throw new IllegalArgumentException(Algorithm.PBKDF2WITHHMACSHA1 + ": salt length mismatch: expected " + SALT_BYTES + ", got " + salt.length);
		}
		if(hash.length != HASH_BYTES) {
			throw new IllegalArgumentException(Algorithm.PBKDF2WITHHMACSHA1 + ": hash length mismatch: expected " + HASH_BYTES + ", got " + hash.length);
		}
	}

	/**
	 * Creates a new hashed password using the given algorithm, salt, and iterations.
	 *
	 * @param algorithm   The algorithm previously used to hash the password
	 * @param iterations  The number of has iterations
	 *
	 * @throws  IllegalArgumentException  when {@code password == null || password.isEmpty()}
	 *                                    on {@code salt.length != algorithm.getSaltBytes()}
	 *                                    or {@code iterations < algorithm.getMinimumIterations()}
	 *                                    or {@code iterations > algorithm.getMaximumIterations()}
	 */
	public HashedPassword(String password, Algorithm algorithm, byte[] salt, int iterations) throws IllegalArgumentException {
		this(algorithm, salt, iterations, algorithm.hash(password, salt, iterations));
	}

	/**
	 * Creates a new hashed password using the given algorithm, {@linkplain Algorithm#generateSalt() a random salt},
	 * and the given iterations
	 * using the provided {@link Random} source.
	 *
	 * @param algorithm   The algorithm previously used to hash the password
	 * @param iterations  The number of has iterations
	 *
	 * @throws  IllegalArgumentException  when {@code password == null || password.isEmpty()}
	 *                                    or {@code iterations < algorithm.getMinimumIterations()}
	 *                                    or {@code iterations > algorithm.getMaximumIterations()}
	 */
	public HashedPassword(String password, Algorithm algorithm, int iterations, Random random) throws IllegalArgumentException {
		this(password, algorithm, algorithm.generateSalt(random), iterations);
	}

	/**
	 * Creates a new hashed password using the given algorithm, {@linkplain Algorithm#generateSalt() a random salt},
	 * and the given iterations
	 * using a default {@link SecureRandom} instance, which is not a
	 * {@linkplain SecureRandom#getInstanceStrong() strong instance} to avoid blocking.
	 *
	 * @param algorithm   The algorithm previously used to hash the password
	 * @param iterations  The number of has iterations
	 *
	 * @throws  IllegalArgumentException  when {@code password == null || password.isEmpty()}
	 *                                    or {@code iterations < algorithm.getMinimumIterations()}
	 *                                    or {@code iterations > algorithm.getMaximumIterations()}
	 */
	public HashedPassword(String password, Algorithm algorithm, int iterations) throws IllegalArgumentException {
		this(password, algorithm, iterations, Identifier.secureRandom);
	}

	/**
	 * Creates a new hashed password using the given algorithm, {@linkplain Algorithm#generateSalt() a random salt},
	 * and {@linkplain Algorithm#getRecommendedIterations() the recommended iterations}
	 * using the provided {@link Random} source.
	 *
	 * @throws  IllegalArgumentException  when {@code password == null || password.isEmpty()}
	 */
	public HashedPassword(String password, Algorithm algorithm, Random random) throws IllegalArgumentException {
		this(password, algorithm, algorithm.getRecommendedIterations(), random);
	}

	/**
	 * Creates a new hashed password using the given algorithm, {@linkplain Algorithm#generateSalt() a random salt},
	 * and {@linkplain Algorithm#getRecommendedIterations() the recommended iterations}
	 * using a default {@link SecureRandom} instance, which is not a
	 * {@linkplain SecureRandom#getInstanceStrong() strong instance} to avoid blocking.
	 *
	 * @throws  IllegalArgumentException  when {@code password == null || password.isEmpty()}
	 */
	public HashedPassword(String password, Algorithm algorithm) throws IllegalArgumentException {
		this(password, algorithm, Identifier.secureRandom);
	}

	/**
	 * Creates a new hashed password using {@linkplain #RECOMMENDED_ALGORITHM the recommended algorithm},
	 * {@linkplain Algorithm#generateSalt() a random salt}, and
	 * {@linkplain Algorithm#getRecommendedIterations() the recommended iterations}
	 * using the provided {@link Random} source.
	 *
	 * @throws  IllegalArgumentException  when {@code password == null || password.isEmpty()}
	 */
	public HashedPassword(String password, Random random) throws IllegalArgumentException {
		this(password, RECOMMENDED_ALGORITHM, random);
	}

	/**
	 * Creates a new hashed password using {@linkplain #RECOMMENDED_ALGORITHM the recommended algorithm},
	 * {@linkplain Algorithm#generateSalt() a random salt}, and
	 * {@linkplain Algorithm#getRecommendedIterations() the recommended iterations}
	 * using a default {@link SecureRandom} instance, which is not a
	 * {@linkplain SecureRandom#getInstanceStrong() strong instance} to avoid blocking.
	 *
	 * @throws  IllegalArgumentException  when {@code password == null || password.isEmpty()}
	 */
	public HashedPassword(String password) throws IllegalArgumentException {
		this(password, Identifier.secureRandom);
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
	// Matches src/main/sql/com/aoindustries/security/HashedPassword.toString-function.sql
	@Override
	public String toString() {
		if(algorithm == null) {
			assert salt == null;
			assert iterations == 0;
			assert hash == null;
			return NO_PASSWORD_VALUE;
		} else {
			assert iterations >= 0;
			return algorithm.toString(salt, iterations, hash);
		}
	}

	/**
	 * Checks if equal to another hashed password, always {@code false} when either is {@link #NO_PASSWORD}.
	 * <p>
	 * Performs comparisons in length-constant time.
	 * <a href="https://crackstation.net/hashing-security.htm">https://crackstation.net/hashing-security.htm</a>
	 * </p>
	 */
	@Override
	public boolean equals(Object obj) {
		if(!(obj instanceof HashedPassword)) return false;
		HashedPassword other = (HashedPassword)obj;
		// All done for length-constant time comparisons
		if(algorithm == null | other.algorithm == null) {
			// Perform an equality check with default settings, just to occupy the same amount of time as if had a key
			boolean discardMe =
				algorithm == other.algorithm
				& slowEquals(DUMMY_SALT, DUMMY_SALT)
				& iterations == other.iterations
				& slowEquals(DUMMY_HASH, DUMMY_HASH);
			assert discardMe == true || discardMe == false : "Suppress unused variable warning";
			return false;
		} else {
			return
				algorithm == other.algorithm
				& slowEquals(salt, other.salt)
				& iterations == other.iterations
				& slowEquals(hash, other.hash);
		}
	}

	/**
	 * The hash code is taken from the last 32 bits of the hash.
	 * The last 32 bits are selected because the first bits might include zero padding when the hash length is not a
	 * multiple of {@link Byte#SIZE}.
	 */
	@Override
	public int hashCode() {
		return (hash == null) ? 0 : IoUtils.bufferToInt(hash, hash.length - Integer.BYTES);
	}

	public Algorithm getAlgorithm() {
		return algorithm;
	}

	/**
	 * @return  No defensive copy
	 */
	@SuppressWarnings("ReturnOfCollectionOrArrayField")
	public byte[] getSalt() {
		return salt;
	}

	public int getIterations() {
		return iterations;
	}

	/**
	 * @return  No defensive copy
	 */
	@SuppressWarnings("ReturnOfCollectionOrArrayField")
	public byte[] getHash() {
		return hash;
	}

	/**
	 * Checks if this matches the provided password, always {@code false} when is {@link #NO_PASSWORD}.
	 * <p>
	 * When {@linkplain #matches(java.lang.String) verifying a user's password}, please check
	 * {@link #isRehashRecommended()} then either set the same
	 * password again or, ideally, generate a new password or prompt the user to reset their password.  This will allow
	 * the stored passwords to keep up with encryption improvements.
	 * </p>
	 * <p>
	 * Performs comparisons in length-constant time.
	 * <a href="https://crackstation.net/hashing-security.htm">https://crackstation.net/hashing-security.htm</a>
	 * </p>
	 *
	 * @see  #isRehashRecommended()
	 */
	public boolean matches(String password) {
		if(algorithm == null || password == null || password.isEmpty()) {
			// Perform a hash with default settings, just to occupy the same amount of time as if had a password
			byte[] dummyHash = RECOMMENDED_ALGORITHM.hash("<<DUMMY>>", DUMMY_SALT, RECOMMENDED_ALGORITHM.getRecommendedIterations());
			boolean dummiesEqual = slowEquals(DUMMY_HASH, dummyHash);
			assert !dummiesEqual;
			return false;
		} else {
			// Hash again with the original salt, iterations, and hash size
			byte[] newHash = algorithm.hash(password, salt, iterations, hash.length);
			return slowEquals(hash, newHash);
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
			final boolean[] hasFailed = {false};
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
									byte[] salt = algorithm.generateSalt();
									long startNanos = output ? System.nanoTime() : 0;
									HashedPassword hashedPassword = new HashedPassword(password, algorithm, salt, recommendedIterations);
									long endNanos = output ? System.nanoTime() : 0;
									if(output) {
										System.out.println(hashedPassword);
										long nanos = endNanos - startNanos;
										System.out.println(
											algorithm.getAlgorithmName() + ": Completed in "
											+ BigDecimal.valueOf(nanos, 6).toPlainString() + " ms"
										);
										System.out.println();
										long millis = nanos / 1_000_000;
										if(millis < SUGGEST_INCREASE_ITERATIONS_MILLIS && recommendedIterations != 0) {
											System.out.flush();
											System.err.println(
												algorithm.getAlgorithmName() + ": Password was hashed in under "
												+ SUGGEST_INCREASE_ITERATIONS_MILLIS
												+ " ms, recommend increasing the value of recommendedIterations (currently "
												+ recommendedIterations + ")"
											);
											System.err.println();
											System.err.flush();
										}
									}
									assert hashedPassword.matches(password);
									assert valueOf(hashedPassword.toString()).matches(password);
								} catch(Error | RuntimeException e) {
									hasFailed[0] = true;
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
						try {
							int recommendedIterations = algorithm.getRecommendedIterations();
							byte[] salt = algorithm.generateSalt();
							HashedPassword hashedPassword = new HashedPassword(
								password,
								algorithm,
								salt,
								recommendedIterations
							);
							System.out.println(hashedPassword);
							assert hashedPassword.matches(password);
							assert valueOf(hashedPassword.toString()).matches(password);
						} catch(Error | RuntimeException e) {
							hasFailed[0] = true;
							System.out.flush();
							System.err.println(algorithm.getAlgorithmName() + ": " + e.toString());
							System.err.flush();
						}
					}
				}
			);
			if(hasFailed[0]) System.exit(SysExits.EX_SOFTWARE);
		}
	}
}
