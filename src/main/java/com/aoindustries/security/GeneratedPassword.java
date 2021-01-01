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
import java.util.function.Supplier;
import java.util.logging.Logger;

/**
 * Unlike {@link Password}, which goes out of its way to protect the password, a
 * generated password provides access to the password value.  This is intended for
 * use when new passwords are generated and need to be accessible to the application.
 *
 * @author  AO Industries, Inc.
 */
public class GeneratedPassword extends Password {

	private final static Logger LOGGER = Logger.getLogger(GeneratedPassword.class.getName());

	/**
	 * @see  #GeneratedPassword(java.util.function.Supplier)
	 */
	private static char[] generatePassword(Supplier<char[]> generator) {
		// Discard any passwords that are generated as all-zero (in the small chance)
		while(true) {
			char[] password = generator.get();
			if(password == null) throw new IllegalArgumentException("Generator created null password");
			if(password.length == 0) throw new IllegalArgumentException("Generator created empty password");
			if(!SecurityUtil.slowAllZero(password)) {
				return password;
			}
			LOGGER.warning("Generator created all-zero password, discarding and trying again");
		}
	}

	/**
	 * Generates a new password using the provided password generator.
	 * <p>
	 * The password will never be all-zeroes, since this would conflict with the representation
	 * of already destroyed.  In the unlikely event the generator creates an all-zero
	 * password, the password will be discarded and another will be generated.  We do recognize that
	 * disallowing certain values from the password space may provide an advantage to attackers
	 * (i.e. Enigma), losing the all-zero password is probably a good choice anyway.
	 * </p>
	 */
	public GeneratedPassword(Supplier<char[]> generator) {
		super(generatePassword(generator));
	}

	/**
	 * Generates a new password using the default password generator
	 * and the provided {@link Random} source.
	 */
	public GeneratedPassword(Random random) {
		this(() -> new SmallIdentifier(random).toCharArray());
	}

	/**
	 * Generates a new password using the default password generator.
	 */
	public GeneratedPassword() {
		this(Identifier.secureRandom);
	}

	/**
	 * Copy constructor.
	 *
	 * @see  #clone()
	 */
	private GeneratedPassword(GeneratedPassword other) {
		super(other);
	}

	@Override
	@SuppressWarnings({"CloneDeclaresCloneNotSupported", "CloneDoesntCallSuperClone"})
	public GeneratedPassword clone() {
		return new GeneratedPassword(this);
	}

	/**
	 * @return  The caller must zero this array once no longer needed.
	 *
	 * @throws IllegalStateException when {@link #isDestroyed()}
	 */
	public char[] getPassword() throws IllegalStateException {
		synchronized(password) {
			if(isDestroyed()) throw new IllegalStateException("Password is already destroyed");
			return Arrays.copyOf(password, password.length);
		}
	}
}
