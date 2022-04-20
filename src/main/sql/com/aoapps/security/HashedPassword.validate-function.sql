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
CREATE OR REPLACE FUNCTION "com.aoapps.security"."HashedPassword.validate" (
  algorithm text,
  salt bytea,
  iterations integer,
  "hash" bytea
)
RETURNS text AS $$
BEGIN
  IF algorithm IS NULL THEN
    IF salt IS NOT NULL THEN
      RETURN 'salt must be null when algorithm is null';
    ELSIF iterations IS DISTINCT FROM 0 THEN
      RETURN 'iterations must be 0 when algorithm is null';
    ELSIF "hash" IS NOT NULL THEN
      RETURN 'hash must be null when algorithm is null';
    END IF;
    -- All is OK
    RETURN null;
  ELSE
    RETURN "com.aoapps.security"."HashedPassword.Algorithm.validate"(algorithm, salt, iterations, "hash");
  END IF;
END;
$$ LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE;

COMMENT ON FUNCTION "com.aoapps.security"."HashedPassword.validate" (text, bytea, integer, bytea) IS
'Matches method com.aoapps.security.HashedPassword.validate';

CREATE OR REPLACE FUNCTION "com.aoapps.security"."HashedPassword.validate" (
  this "com.aoapps.security"."<HashedPassword>"
)
RETURNS text AS $$
BEGIN
  RETURN "com.aoapps.security"."HashedPassword.validate"(
    this.algorithm,
    this.salt,
    this.iterations,
    this."hash"
  );
END;
$$ LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE;

COMMENT ON FUNCTION "com.aoapps.security"."HashedPassword.validate" (
  "com.aoapps.security"."<HashedPassword>"
) IS
'Matches method com.aoapps.security.HashedPassword.validate';
