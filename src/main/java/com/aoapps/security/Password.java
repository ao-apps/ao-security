/*
 * ao-security - Best-practices security made usable.
 * Copyright (C) 2021, 2022  AO Industries, Inc.
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

import java.io.Externalizable;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Optional;
import javax.security.auth.Destroyable;

/**
 * Represents plaintext password characters, with support for wiping the contents.
 * This is used in preference to <code>char[]</code> as a matter of both convenience and protection.
 * <p>
 * This does not provide any access to the given password.  It is a password black hole:
 * gone forever from outside observers.
 * </p>
 * <p>
 * Instances of this class are thread-safe.
 * </p>
 * <p>
 * This class intentionally does not implement {@link #equals(java.lang.Object)} and {@link #hashCode()}, as it is not
 * intended to be used in data structures or any complex manipulation.  It is solely meant to safely carry a
 * password.
 * </p>
 * <p>
 * This class also does not implement {@link Serializable} or {@link Externalizable}.  Applications that need to send
 * passwords across the wire must use another mechanism.  Applications that need to store passwords should be using
 * {@link HashedPassword}.
 * </p>
 *
 * @author  AO Industries, Inc.
 */
@SuppressWarnings({"EqualsAndHashcode", "overrides"})
// Java 17: sealed to be extended by UnprotectedPassword only
public class Password implements Destroyable, AutoCloseable, Cloneable {

  /**
   * A constant used to mask passwords.  This is always returned by
   * {@link #toString()}.
   */
  public static final String MASKED_PASSWORD = "************";

  /**
   * Gets a new password or {@link Optional#empty()} when {@code password == null || password.length == 0}.
   *
   * @param  password  Is zeroed before this method returns.  If the original password is
   *                   needed, pass a copy to this method.
   *
   * @throws IllegalArgumentException when {@code password} is already destroyed (contains all zeroes).
   *
   * @see #Password(char[])
   */
  public static Optional<Password> valueOf(char[] password) throws IllegalArgumentException {
    return (password == null || password.length == 0)
        ? Optional.empty()
        : Optional.of(new Password(password));
  }

  /**
   * Contains the password or all zeroes once destroyed.
   * <p>
   * All uses must be synchronized on this <code>char[]</code> itself.
   * </p>
   */
  final char[] password;

  /**
   * @param  password  Is zeroed before this method returns.  If the original password is
   *                   needed, pass a copy to this method.
   *
   * @throws IllegalArgumentException when {@code password == null || password.length == 0} or when {@code password}
   *                                  is already destroyed (contains all zeroes).
   *
   * @see #valueOf(char[])
   */
  public Password(char[] password) throws IllegalArgumentException {
    if (password == null || password.length == 0) {
      throw new IllegalArgumentException("Refusing to create empty password");
    } else {
      try {
        char[] copy = Arrays.copyOf(password, password.length);
        Arrays.fill(password, (char) 0);
        password = null;
        assert copy.length > 0;
        // length-constant time implementation:
        if (SecurityUtil.slowAllZero(copy)) {
          throw new IllegalArgumentException("Refusing to create destroyed password");
        } else {
          this.password = copy;
        }
      } finally {
        if (password != null) {
          Arrays.fill(password, (char) 0);
        }
      }
    }
  }

  /**
   * Copy constructor.
   *
   * @see  #clone()
   */
  Password(Password other) {
    synchronized (other.password) {
      this.password = Arrays.copyOf(other.password, other.password.length);
    }
  }

  /**
   * @return Returns {@link #MASKED_PASSWORD} always.
   */
  @Override
  public String toString() {
    return MASKED_PASSWORD;
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof Password)) {
      return false;
    }
    Password other = (Password) obj;
    // Create a copy to avoid potential deadlock of locking on both
    char[] copy2;
    synchronized (other.password) {
      copy2 = Arrays.copyOf(other.password, other.password.length);
    }
    try {
      synchronized (password) {
        // length-constant time
        return
            !SecurityUtil.slowAllZero(password)
                & !SecurityUtil.slowAllZero(copy2)
                &  SecurityUtil.slowEquals(password, copy2);
      }
    } finally {
      Arrays.fill(copy2, (char) 0);
    }
  }

  @Override
  @SuppressWarnings({"CloneDeclaresCloneNotSupported", "CloneDoesntCallSuperClone"})
  public Password clone() {
    return new Password(this);
  }

  @Override
  public void destroy() {
    synchronized (password) {
      Arrays.fill(password, (char) 0);
    }
  }

  @Override
  public boolean isDestroyed() {
    synchronized (password) {
      return SecurityUtil.slowAllZero(password);
    }
  }

  /**
   * {@linkplain #destroy() Destroys the password} on auto-close.
   * This use for support of try-with-resources.
   */
  @Override
  public void close() {
    destroy();
  }
}
