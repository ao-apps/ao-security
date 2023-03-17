/*
 * ao-security - Best-practices security made usable.
 * Copyright (C) 2012, 2013, 2014, 2016, 2017, 2020, 2021, 2022, 2023  AO Industries, Inc.
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

import static com.aoapps.lang.math.UnsignedLong.divide;
import static com.aoapps.lang.math.UnsignedLong.remainder;

import com.aoapps.lang.io.IoUtils;
import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

/**
 * A 128-bit random identifier internally stored as two long values.
 *
 * @author  AO Industries, Inc.
 */
// Matches src/main/sql/com/aoapps/security/Identifier-type.sql
public final class Identifier implements Serializable, Comparable<Identifier> {

  private static final long serialVersionUID = 1L;

  /**
   * @see  #toString()
   */
  // Matches src/main/sql/com/aoapps/security/Identifier.valueOf-function.sql
  public static Identifier valueOf(String encoded) throws IllegalArgumentException {
    return new Identifier(encoded);
  }

  static final long BASE = 57;

  /**
   * The characters that represent each value.  These are all URL-safe without encoding.  These are selected to
   * minimize ambiguity, favoring numeric digits where ambiguous.
   * <p>
   * If we were to do this again, we would choose to reassemble these characters into ascending ASCII order.  That way
   * a simple lexical ordering would be the same as the decoded numeric value ordering.  This is not important, so we
   * will not change it, but this should be a minor consideration to others implementing similar systems.
   * </p>
   */
  private static final char[] CHARACTERS = {
      'A', /*'B',*/ 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
      'N', /*'O',*/ 'P', /*'Q',*/ 'R', /*'S',*/ 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
      'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', /*'l',*/ 'm',
      'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
  };

  static {
    assert CHARACTERS.length == BASE;
  }

  /**
   * The number of characters required to represent a 64-but number in base {@link #BASE}.
   */
  static final int NUM_CHARACTERS = 11;

  private static final char LOWEST_CHAR = '0';
  private static final char HIGHEST_CHAR = 'z';

  private static final int[] values = new int[HIGHEST_CHAR + 1 - LOWEST_CHAR];

  static {
    Arrays.fill(values, -1);
    for (int i = 0; i < BASE; i++) {
      values[CHARACTERS[i] - LOWEST_CHAR] = i;
    }
  }

  /**
   * Gets the character for the low-order modulus BASE a long value.
   */
  // Matches src/main/sql/com/aoapps/security/Identifier.getCharacter-function.sql
  static char getCharacter(long value) {
    int index = (int) remainder(value, BASE);
    return CHARACTERS[index];
  }

  /**
   * Gets the value for a character as a long.
   *
   * @throws IllegalArgumentException when character is not valid
   */
  // Matches src/main/sql/com/aoapps/security/Identifier.getValue-function.sql
  private static long getValue(char ch) {
    if (ch >= LOWEST_CHAR && ch <= HIGHEST_CHAR) {
      int value = values[ch - LOWEST_CHAR];
      if (value != -1) {
        return value;
      }
    }
    //if (ch >= 'A' && ch <= 'Z') {
    //  return (long)(ch - 'A');
    //}
    //if (ch >= 'a' && ch <= 'z') {
    //  return (long)(ch - 'a' + 26);
    //}
    //if (ch >= '0' && ch <= '4') {
    //  return (long)(ch - '0' + 52);
    //}
    throw new IllegalArgumentException(Character.toString(ch));
  }

  /**
   * Decodes one set of {@literal #NUM_CHARACTERS} characters to a long.
   *
   * @throws IllegalArgumentException when any character is not valid or resulting number would be out of range
   */
  // Matches src/main/sql/com/aoapps/security/Identifier.decode-function.sql
  // TODO: Fail when encoded != decoded, since some ambiguity exists due to bit overflow.  This could be narrowed down to specific range and specifically excluded from parsing
  //       Also check same in PostgreSQL implementation
  //       Check SmallIdentifier and other uses
  //       Add test to find and assert the boundary condition
  static long decode(String encoded) {
    assert encoded.length() == NUM_CHARACTERS;
    return
        getValue(encoded.charAt(0)) * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE
            + getValue(encoded.charAt(1)) * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE
            + getValue(encoded.charAt(2)) * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE
            + getValue(encoded.charAt(3)) * BASE * BASE * BASE * BASE * BASE * BASE * BASE
            + getValue(encoded.charAt(4)) * BASE * BASE * BASE * BASE * BASE * BASE
            + getValue(encoded.charAt(5)) * BASE * BASE * BASE * BASE * BASE
            + getValue(encoded.charAt(6)) * BASE * BASE * BASE * BASE
            + getValue(encoded.charAt(7)) * BASE * BASE * BASE
            + getValue(encoded.charAt(8)) * BASE * BASE
            + getValue(encoded.charAt(9)) * BASE
            + getValue(encoded.charAt(10));
  }

  /**
   * Note: This is not a {@linkplain SecureRandom#getInstanceStrong() strong instance} to avoid blocking.
   */
  static final SecureRandom secureRandom = new SecureRandom();

  private final long hi;
  private final long lo;

  /**
   * Creates a new, random {@link Identifier} using a default {@link SecureRandom} instance, which is not a
   * {@linkplain SecureRandom#getInstanceStrong() strong instance} to avoid blocking.
   */
  public Identifier() {
    this((Random) secureRandom);
  }

  /**
   * Creates a new, random {@link Identifier} using the provided {@link Random} source.
   *
   * @deprecated  Please use {@link SecureRandom}.  This method will stay, but will remain deprecated since it should
   *              only be used after careful consideration.
   */
  @Deprecated // Java 9: (forRemoval = false)
  public Identifier(Random random) {
    byte[] bytes = new byte[Long.BYTES * 2];
    random.nextBytes(bytes);
    hi = IoUtils.bufferToLong(bytes);
    lo = IoUtils.bufferToLong(bytes, Long.BYTES);
  }

  /**
   * Creates a new, random {@link Identifier} using the provided {@link SecureRandom} source.
   */
  public Identifier(SecureRandom secureRandom) {
    this((Random) secureRandom);
  }

  public Identifier(long hi, long lo) {
    this.hi = hi;
    this.lo = lo;
  }

  /**
   * @see  #toString()
   */
  // Matches src/main/sql/com/aoapps/security/Identifier.valueOf-function.sql
  public Identifier(String encoded) throws IllegalArgumentException {
    if (encoded.length() != (NUM_CHARACTERS * 2)) {
      throw new IllegalArgumentException();
    }
    this.hi = decode(encoded.substring(0, NUM_CHARACTERS));
    this.lo = decode(encoded.substring(NUM_CHARACTERS));
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof Identifier)) {
      return false;
    }
    return equals((Identifier) obj);
  }

  /**
   * Performs comparisons in length-constant time.
   * <a href="https://crackstation.net/hashing-security.htm">https://crackstation.net/hashing-security.htm</a>
   */
  public boolean equals(Identifier other) {
    if (other == null) {
      return false;
    }
    int diff = 0;
    diff |= hi ^ other.hi;
    diff |= lo ^ other.lo;
    return diff == 0;
  }

  @Override
  public int hashCode() {
    // The values should be well distributed, any set of 32 bits should be equally good.
    return (int) lo;
  }

  /**
   * The external representation is a string of characters encoded in base {@literal #BASE}, with
   * the first {@literal #NUM_CHARACTERS} characters for "hi" and the last {@literal #NUM_CHARACTERS} characters for "lo".
   */
  // Matches src/main/sql/com/aoapps/security/Identifier.toString-function.sql
  public char[] toCharArray() {
    return new char[]{
        getCharacter(divide(hi, BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE)),
        getCharacter(divide(hi, BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE)),
        getCharacter(divide(hi, BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE)),
        getCharacter(divide(hi, BASE * BASE * BASE * BASE * BASE * BASE * BASE)),
        getCharacter(divide(hi, BASE * BASE * BASE * BASE * BASE * BASE)),
        getCharacter(divide(hi, BASE * BASE * BASE * BASE * BASE)),
        getCharacter(divide(hi, BASE * BASE * BASE * BASE)),
        getCharacter(divide(hi, BASE * BASE * BASE)),
        getCharacter(divide(hi, BASE * BASE)),
        getCharacter(divide(hi, BASE)),
        getCharacter(hi),
        getCharacter(divide(lo, BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE)),
        getCharacter(divide(lo, BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE)),
        getCharacter(divide(lo, BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE)),
        getCharacter(divide(lo, BASE * BASE * BASE * BASE * BASE * BASE * BASE)),
        getCharacter(divide(lo, BASE * BASE * BASE * BASE * BASE * BASE)),
        getCharacter(divide(lo, BASE * BASE * BASE * BASE * BASE)),
        getCharacter(divide(lo, BASE * BASE * BASE * BASE)),
        getCharacter(divide(lo, BASE * BASE * BASE)),
        getCharacter(divide(lo, BASE * BASE)),
        getCharacter(divide(lo, BASE)),
        getCharacter(lo)
    };
  }

  /**
   * The external representation is a string of characters encoded in base {@literal #BASE}, with
   * the first {@literal #NUM_CHARACTERS} characters for "hi" and the last {@literal #NUM_CHARACTERS} characters for "lo".
   */
  // Matches src/main/sql/com/aoapps/security/Identifier.toString-function.sql
  @Override
  public String toString() {
    return new String(toCharArray());
  }

  /**
   * Unsigned ordering.
   */
  @Override
  public int compareTo(Identifier other) {
    int diff = Long.compareUnsigned(hi, other.hi);
    if (diff != 0) {
      return diff;
    }
    return Long.compareUnsigned(lo, other.lo);
  }

  public long getHi() {
    return hi;
  }

  public long getLo() {
    return lo;
  }

  @SuppressWarnings("UseOfSystemOutOrSystemErr")
  public static void main(String[] args) {
    System.out.println(new Identifier());
  }
}
