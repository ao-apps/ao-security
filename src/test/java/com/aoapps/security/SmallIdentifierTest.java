/*
 * ao-security - Best-practices security made usable.
 * Copyright (C) 2014, 2016, 2017, 2020, 2021, 2022  AO Industries, Inc.
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

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Tests the SmallIdentifier class.
 *
 * @author  AO Industries, Inc.
 */
public class SmallIdentifierTest extends TestCase {

  public SmallIdentifierTest(String testName) {
    super(testName);
  }

  public static Test suite() {
    TestSuite suite = new TestSuite(SmallIdentifierTest.class);
    return suite;
  }

  public void testDiscrepancyWithDatabaseFunction() {
    SmallIdentifier parsed = new SmallIdentifier("bWMZti51JU8");
    assertEquals(8442361102747480762L, parsed.getValue());
    String formatted = parsed.toString();
    assertEquals("bWMZti51JU8", formatted);
  }
}
