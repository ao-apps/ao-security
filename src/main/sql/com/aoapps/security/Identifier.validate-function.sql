/*
 * ao-security - Best-practices security made usable.
 * Copyright (C) 2020, 2021, 2022  AO Industries, Inc.
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
CREATE OR REPLACE FUNCTION "com.aoapps.security"."Identifier.validate" (hi bigint, lo bigint)
RETURNS text AS $$
BEGIN
  IF hi IS NULL THEN
    RETURN 'hi may not be null';
  ELSIF lo IS NULL THEN
    RETURN 'lo may not be null';
  ELSE
    RETURN null;
  END IF;
END;
$$ LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE;

COMMENT ON FUNCTION "com.aoapps.security"."Identifier.validate" (bigint, bigint) IS
'Enforces neither hi nor lo may be null.';

CREATE OR REPLACE FUNCTION "com.aoapps.security"."Identifier.validate" (
  this "com.aoapps.security"."<Identifier>"
)
RETURNS text AS $$
BEGIN
  RETURN "com.aoapps.security"."Identifier.validate"(this.hi, this.lo);
END;
$$ LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE;

COMMENT ON FUNCTION "com.aoapps.security"."Identifier.validate" (
  "com.aoapps.security"."<Identifier>"
) IS
'Enforces neither hi nor lo may be null.';
