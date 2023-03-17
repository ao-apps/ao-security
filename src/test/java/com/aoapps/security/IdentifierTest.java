/*
 * ao-security - Best-practices security made usable.
 * Copyright (C) 2012, 2016, 2017, 2020, 2021, 2022, 2023  AO Industries, Inc.
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

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/**
 * Tests the Identifier class.
 *
 * @author  AO Industries, Inc.
 */
public class IdentifierTest {

  @Test
  @SuppressWarnings("UseOfSystemOutOrSystemErr")
  public void testToStringValueOfEquals() {
    //long divider = (BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE);
    //System.out.println("DEBUG: " + divider+" : " + (-1L / divider));
    //System.out.println("DEBUG: "+(Long.MAX_VALUE / (BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE)));
    //System.out.println("DEBUG: "+(Long.MIN_VALUE / (BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE)));
    //System.out.println("DEBUG: "+((-1) / (BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE * BASE)));
    //System.out.println("DEBUG: " + new Identifier(-1L, 0xffffffffffffffffl));
    for (int i = 0; i < 100000; i++) {
      Identifier i1 = new Identifier();
      String s1 = i1.toString();
      Identifier i2 = Identifier.valueOf(s1);
      String s2 = i2.toString();
      if (
          !s1.equals(s2)
              || !i1.equals(i2)
      ) {
        System.out.print(s1);
        System.out.print(' ');
        System.out.print(Long.toHexString(i1.getHi()));
        System.out.println(Long.toHexString(i1.getLo()));
        System.out.print(s2);
        System.out.print(' ');
        System.out.print(Long.toHexString(i2.getHi()));
        System.out.println(Long.toHexString(i2.getLo()));
      }
      assertEquals(s1, s2);
      assertEquals(i1, i2);
    }
  }
}
