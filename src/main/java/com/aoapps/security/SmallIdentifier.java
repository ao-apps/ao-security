/*
 * ao-security - Best-practices security made usable.
 * Copyright (C) 2014, 2016, 2017, 2020, 2021  AO Industries, Inc.
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

import com.aoapps.lang.io.IoUtils;
import static com.aoapps.lang.math.UnsignedLong.divide;
import static com.aoapps.security.Identifier.BASE;
import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Random;

/**
 * A 64-bit random identifier internally stored as a long value.
 *
 * @author  AO Industries, Inc.
 */
// Matches src/main/sql/com/aoapps/security/SmallIdentifier-type.sql
public final class SmallIdentifier implements Serializable, Comparable<SmallIdentifier> {

	private static final long serialVersionUID = 1L;

	/**
	 * @see  #toString()
	 */
	// Matches src/main/sql/com/aoapps/security/SmallIdentifier.valueOf-function.sql
	public static SmallIdentifier valueOf(String encoded) throws IllegalArgumentException {
		return new SmallIdentifier(encoded);
	}

	private final long value;

	/**
	 * Creates a new, random {@link SmallIdentifier} using a default {@link SecureRandom} instance, which is not a
	 * {@linkplain SecureRandom#getInstanceStrong() strong instance} to avoid blocking.
	 */
	public SmallIdentifier() {
		this((Random)Identifier.secureRandom);
	}

	/**
	 * Creates a new, random {@link SmallIdentifier} using the provided {@link Random} source.
	 *
	 * @deprecated  Please use {@link SecureRandom}.  This method will stay, but will remain deprecated since it should
	 *              only be used after careful consideration.
	 */
	@Deprecated // Java 9: (forRemoval = false)
	public SmallIdentifier(Random random) {
		byte[] bytes = new byte[Long.BYTES];
		random.nextBytes(bytes);
		value = IoUtils.bufferToLong(bytes);
	}

	/**
	 * Creates a new, random {@link SmallIdentifier} using the provided {@link SecureRandom} source.
	 */
	public SmallIdentifier(SecureRandom secureRandom) {
		this((Random)secureRandom);
	}

	public SmallIdentifier(long value) {
		this.value = value;
	}

	/**
	 * @see  #toString()
	 */
	// Matches src/main/sql/com/aoapps/security/SmallIdentifier.valueOf-function.sql
	public SmallIdentifier(String encoded) throws IllegalArgumentException {
		if(encoded.length()!=11) throw new IllegalArgumentException();
		this.value = Identifier.decode(encoded);
	}

	@Override
	public boolean equals(Object obj) {
		if(!(obj instanceof SmallIdentifier)) return false;
		return equals((SmallIdentifier)obj);
	}

	public boolean equals(SmallIdentifier other) {
		return
			other!=null
			&& value==other.value
		;
	}

	@Override
	public int hashCode() {
		// The values should be well distributed, any set of 32 bits should be equally good.
		return (int)value;
	}

	/**
	 * The external representation is a string of characters encoded in base 57, with
	 * 11 characters for "value".
	 *
	 * @see  #toString()
	 */
	public char[] toCharArray() {
		return new char[] {
			Identifier.getCharacter(divide(value, BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE)),
			Identifier.getCharacter(divide(value, BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE)),
			Identifier.getCharacter(divide(value, BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE)),
			Identifier.getCharacter(divide(value, BASE * BASE * BASE * BASE * BASE * BASE * BASE)),
			Identifier.getCharacter(divide(value, BASE * BASE * BASE * BASE * BASE * BASE)),
			Identifier.getCharacter(divide(value, BASE * BASE * BASE * BASE * BASE)),
			Identifier.getCharacter(divide(value, BASE * BASE * BASE * BASE)),
			Identifier.getCharacter(divide(value, BASE * BASE * BASE)),
			Identifier.getCharacter(divide(value, BASE * BASE)),
			Identifier.getCharacter(divide(value, BASE)),
			Identifier.getCharacter(value)
		};
	}

	/**
	 * The external representation is a string of characters encoded in base 57, with
	 * 11 characters for "value".
	 *
	 * @see  #toCharArray()
	 */
	// Matches src/main/sql/com/aoapps/security/SmallIdentifier.toString-function.sql
	@Override
	public String toString() {
		return new String(toCharArray());
	}

	/**
	 * Unsigned ordering.
	 */
	@Override
	public int compareTo(SmallIdentifier other) {
		return Long.compareUnsigned(value, other.value);
	}

	public long getValue() {
		return value;
	}

	@SuppressWarnings("UseOfSystemOutOrSystemErr")
	public static void main(String[] args) {
		System.out.println(new SmallIdentifier());
	}
}
