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
 * along with ao-security.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.aoapps.security;

import com.aoapps.lang.function.ConsumerE;
import com.aoapps.lang.function.FunctionE;
import com.aoapps.lang.function.PredicateE;
import com.aoapps.lang.function.SupplierE;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Logger;

/**
 * Unlike {@link Key}, which goes out of its way to protect the key, an unprotected key provides access
 * to the key value.  This is intended for when the key needs to be accessible to the application, such as
 * setting a cookie value to a generated authentication token.
 *
 * @author  AO Industries, Inc.
 */
public class UnprotectedKey extends Key {

	private static final Logger logger = Logger.getLogger(UnprotectedKey.class.getName());

	/**
	 * @param  <Ex>  An arbitrary exception type that may be thrown
	 *
	 * @see  #UnprotectedKey(java.util.function.Supplier)
	 */
	private static <Ex extends Throwable> byte[] generateKey(SupplierE<? extends byte[], Ex> generator) throws Ex {
		// Discard any keys that are generated as all-zero (in the small chance)
		final int TRIES = 100;
		for(int i = 0; i < TRIES; i++) {
			byte[] key = generator.get();
			if(key == null) throw new IllegalArgumentException("Generator created null key");
			if(key.length == 0) throw new IllegalArgumentException("Generator created empty key");
			if(!SecurityUtil.slowAllZero(key)) {
				return key;
			}
			logger.warning("Generator created all-zero key, discarding and trying again");
		}
		// Generator is broken; don't loop forever
		throw new IllegalArgumentException("Generator is only creating all-zero keys, tried " + TRIES + " times");
	}

	/**
	 * @param  key  Is zeroed before this method returns.  If the original key is
	 *              needed, pass a copy to this method.
	 *
	 * @throws IllegalArgumentException when {@code key == null || key.length == 0} or when {@code key}
	 *                                  is already destroyed (contains all zeroes).
	 */
	public UnprotectedKey(byte[] key) throws IllegalArgumentException {
		super(key);
	}

	/**
	 * Generates a new key using the provided key generator.
	 * <p>
	 * The key will never be all-zeroes, since this would conflict with the representation
	 * of already destroyed.  In the unlikely event the generator creates an all-zero
	 * key, the key will be discarded and another will be generated.  We do recognize that
	 * disallowing certain values from the key space may provide an advantage to attackers
	 * (i.e. Enigma), losing the all-zero key is probably a good choice anyway.
	 * </p>
	 *
	 * @param  <Ex>  An arbitrary exception type that may be thrown
	 */
	public <Ex extends Throwable> UnprotectedKey(SupplierE<? extends byte[], Ex> generator) throws Ex {
		this(generateKey(generator));
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
	public UnprotectedKey(int keyBytes, Random random) throws IllegalArgumentException {
		this(() -> {
			byte[] newKey = new byte[keyBytes];
			random.nextBytes(newKey);
			return newKey;
		});
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
	public UnprotectedKey(int keyBytes) throws IllegalArgumentException {
		this(keyBytes, Identifier.secureRandom);
	}

	/**
	 * Copy constructor.
	 *
	 * @see  #clone()
	 */
	private UnprotectedKey(UnprotectedKey other) {
		super(other);
	}

	@Override
	@SuppressWarnings({"CloneDeclaresCloneNotSupported", "CloneDoesntCallSuperClone"})
	public UnprotectedKey clone() {
		return new UnprotectedKey(this);
	}

	/**
	 * @return  The caller must zero this array once no longer needed.
	 *
	 * @throws IllegalStateException when {@link #isDestroyed()}
	 *
	 * @see  #invoke(com.aoapps.lang.function.FunctionE)
	 * @see  #accept(com.aoapps.lang.function.ConsumerE)
	 * @see  #test(com.aoapps.lang.function.PredicateE)
	 */
	byte[] getKey() throws IllegalStateException {
		synchronized(key) {
			if(isDestroyed()) throw new IllegalStateException("Key is already destroyed");
			return Arrays.copyOf(key, key.length);
		}
	}

	/**
	 * Calls a function, providing a copy of the key.
	 * The copy of the key is zeroed once the function returns.
	 *
	 * @param  <Ex>  An arbitrary exception type that may be thrown
	 *
	 * @throws IllegalStateException when {@link #isDestroyed()}
	 */
	public <R, Ex extends Throwable> R invoke(FunctionE<? super byte[], R, Ex> function) throws IllegalStateException, Ex {
		byte[] copy = getKey();
		try {
			return function.apply(copy);
		} finally {
			Arrays.fill(copy, (byte)0);
		}
	}

	/**
	 * Calls a consumer, providing a copy of the key.
	 * The copy of the key is zeroed once the consumer returns.
	 *
	 * @param  <Ex>  An arbitrary exception type that may be thrown
	 *
	 * @throws IllegalStateException when {@link #isDestroyed()}
	 */
	public <Ex extends Throwable> void accept(ConsumerE<? super byte[], Ex> consumer) throws IllegalStateException, Ex {
		byte[] copy = getKey();
		try {
			consumer.accept(copy);
		} finally {
			Arrays.fill(copy, (byte)0);
		}
	}

	/**
	 * Calls a predicate, providing a copy of the key.
	 * The copy of the key is zeroed once the predicate returns.
	 *
	 * @param  <Ex>  An arbitrary exception type that may be thrown
	 *
	 * @throws IllegalStateException when {@link #isDestroyed()}
	 */
	public <Ex extends Throwable> boolean test(PredicateE<? super byte[], Ex> predicate) throws IllegalStateException, Ex {
		byte[] copy = getKey();
		try {
			return predicate.test(copy);
		} finally {
			Arrays.fill(copy, (byte)0);
		}
	}
}
