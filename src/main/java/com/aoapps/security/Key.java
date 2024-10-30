/*
 * ao-security - Best-practices security made usable.
 * Copyright (C) 2021, 2022, 2023, 2024  AO Industries, Inc.
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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.Externalizable;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Optional;
import javax.security.auth.Destroyable;

/**
 * Represents plaintext random keys, with support for wiping the contents.
 * This is used in preference to <code>byte[]</code> as a matter of both convenience and protection.
 *
 * <p>This does not provide any access to the given key.  It is a key black hole:
 * gone forever from outside observers.  The only way a key is available is through
 * {@linkplain UnprotectedKey a newly generated key}.</p>
 *
 * <p>Instances of this class are thread-safe.</p>
 *
 * <p>This class intentionally does not implement {@link #equals(java.lang.Object)} and {@link #hashCode()}, as it is not
 * intended to be used in data structures or any complex manipulation.  It is solely meant to safely carry a
 * key.</p>
 *
 * <p>This class also does not implement {@link Serializable} or {@link Externalizable}.  Applications that need to send
 * keys across the wire must use another mechanism.  Applications that need to store keys should be using
 * {@link HashedKey}.</p>
 *
 * @author  AO Industries, Inc.
 */
// TODO: Should the key contain the algorithm, too?
// Java 17: sealed to be extended by UnprotectedKey only
@SuppressFBWarnings("PI_DO_NOT_REUSE_PUBLIC_IDENTIFIERS_CLASS_NAMES")
public class Key implements Destroyable, AutoCloseable, Cloneable {

  /**
   * Gets a new key or {@link Optional#empty()} when {@code key == null || key.length == 0}.
   *
   * @param  key  Is zeroed before this method returns.  If the original key is
   *              needed, pass a copy to this method.
   *
   * @throws IllegalArgumentException when {@code key} is already destroyed (contains all zeroes).
   *
   * @see #Key(byte[])
   */
  public static Optional<Key> valueOf(byte[] key) throws IllegalArgumentException {
    return (key == null || key.length == 0)
        ? Optional.empty()
        : Optional.of(new Key(key));
  }

  /**
   * Contains the key or all zeroes once destroyed.
   *
   * <p>All uses must be synchronized on this <code>byte[]</code> itself.</p>
   */
  final byte[] key;

  /**
   * @param  key  Is zeroed before this method returns.  If the original key is
   *              needed, pass a copy to this method.
   *
   * @throws IllegalArgumentException when {@code key == null || key.length == 0} or when {@code key}
   *                                  is already destroyed (contains all zeroes).
   *
   * @see #valueOf(byte[])
   */
  @SuppressFBWarnings("CT_CONSTRUCTOR_THROW")
  public Key(byte[] key) throws IllegalArgumentException {
    if (key == null || key.length == 0) {
      throw new IllegalArgumentException("Refusing to create empty key");
    } else {
      try {
        byte[] copy = Arrays.copyOf(key, key.length);
        Arrays.fill(key, (byte) 0);
        key = null;
        assert copy.length > 0;
        // length-constant time implementation:
        if (SecurityUtil.slowAllZero(copy)) {
          throw new IllegalArgumentException("Refusing to create destroyed key");
        } else {
          this.key = copy;
        }
      } finally {
        if (key != null) {
          Arrays.fill(key, (byte) 0);
        }
      }
    }
  }

  /**
   * Copy constructor.
   *
   * @see  #clone()
   */
  Key(Key other) {
    synchronized (other.key) {
      this.key = Arrays.copyOf(other.key, other.key.length);
    }
  }

  @Override
  public String toString() {
    return isDestroyed()
        ? "\uD83D\uDC7B"  // Ghost emoji
        : "\uD83D\uDE4A"; // Speak-no-evil monkey emoji
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof Key)) {
      return false;
    }
    Key other = (Key) obj;
    // Create a copy to avoid potential deadlock of locking on both
    byte[] copy2;
    synchronized (other.key) {
      copy2 = Arrays.copyOf(other.key, other.key.length);
    }
    try {
      synchronized (key) {
        // length-constant time
        return
            !SecurityUtil.slowAllZero(key)
                & !SecurityUtil.slowAllZero(copy2)
                &  SecurityUtil.slowEquals(key, copy2);
      }
    } finally {
      Arrays.fill(copy2, (byte) 0);
    }
  }

  /**
   * Uses default implementation from {@link Object#hashCode()}.
   * Any meaningful implementation could leak private key information.
   * Use {@link UnprotectedKey} instead when needing to use in hash-based data structures.
   */
  @Override
  public int hashCode() {
    return super.hashCode();
  }

  @Override
  @SuppressWarnings({"CloneDeclaresCloneNotSupported", "CloneDoesntCallSuperClone"})
  @SuppressFBWarnings(
      value = "CN_IDIOM_NO_SUPER_CALL",
      justification = "Delegating to a copy constructor")
  public Key clone() {
    return new Key(this);
  }

  @Override
  public void destroy() {
    synchronized (key) {
      Arrays.fill(key, (byte) 0);
    }
  }

  @Override
  public boolean isDestroyed() {
    synchronized (key) {
      return SecurityUtil.slowAllZero(key);
    }
  }

  /**
   * {@linkplain #destroy() Destroys the key} on auto-close.
   * This use for support of try-with-resources.
   */
  @Override
  public void close() {
    destroy();
  }
}
