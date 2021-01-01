/*
 * ao-security - Best-practices security made usable.
 * Copyright (C) 2021  AO Industries, Inc.
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

import java.util.Arrays;
import java.util.Random;
import java.util.logging.Logger;

/**
 * Unlike {@link Key}, which goes out of its way to protect the key, a
 * generated key provides access to the key value.  This is intended for
 * use when new keys are generated and need to be accessible to the application.
 *
 * @author  AO Industries, Inc.
 */
public class GeneratedKey extends Key {

	private final static Logger LOGGER = Logger.getLogger(GeneratedKey.class.getName());

	/**
	 * @see  #GeneratedKey(int, java.util.Random)
	 */
	private static byte[] generateKey(int keyBytes, Random random) {
		if(keyBytes == 0) {
			throw new IllegalArgumentException("Refusing to generate empty key");
		} else {
			// Discard any keys that are generated as all-zero (in the small chance)
			byte[] key = new byte[keyBytes];
			while(true) {
				random.nextBytes(key);
				if(!SecurityUtil.slowAllZero(key)) {
					return key;
				}
				LOGGER.warning("Random source generated all-zero key, discarding and trying again");
			}
		}
	}

	/**
	 * Generates a new key of the given number of bytes
	 * using the provided {@link Random} source.
	 * <p>
	 * The key will never be all-zeroes, since this would conflict with the representation
	 * of already destroyed.  In the unlikely event the random source generates an all-zero
	 * key, the key will be discarded and another will be generated.  We do recognize that
	 * disallowing certain values from the key space may provide an advantage to attackers
	 * (i.e. Enigma), losing the all-zero key is probably a good choice anyway.
	 * </p>
	 *
	 * @throws IllegalArgumentException when {@code keyBytes == 0}
	 */
	public GeneratedKey(int keyBytes, Random random) throws IllegalArgumentException {
		super(generateKey(keyBytes, random));
	}

	/**
	 * Generates a new key of the given number of bytes.
	 * <p>
	 * The key will never be all-zeroes, since this would conflict with the representation
	 * of already destroyed.  In the unlikely event the random source generates an all-zero
	 * key, the key will be discarded and another will be generated.  We do recognize that
	 * disallowing certain values from the key space may provide an advantage to attackers
	 * (i.e. Enigma), losing the all-zero key is probably a good choice anyway.
	 * </p>
	 *
	 * @throws IllegalArgumentException when {@code keyBytes == 0}
	 */
	public GeneratedKey(int keyBytes) throws IllegalArgumentException {
		this(keyBytes, Identifier.secureRandom);
	}

	/**
	 * Copy constructor.
	 *
	 * @see  #clone()
	 */
	private GeneratedKey(GeneratedKey other) {
		super(other);
	}

	@Override
	@SuppressWarnings({"CloneDeclaresCloneNotSupported", "CloneDoesntCallSuperClone"})
	public GeneratedKey clone() {
		return new GeneratedKey(this);
	}

	/**
	 * @return  The caller must zero this array once no longer needed.
	 *
	 * @throws IllegalStateException when {@link #isDestroyed()}
	 */
	public byte[] getKey() throws IllegalStateException {
		synchronized(key) {
			if(isDestroyed()) throw new IllegalStateException("Key is already destroyed");
			return Arrays.copyOf(key, key.length);
		}
	}
}
