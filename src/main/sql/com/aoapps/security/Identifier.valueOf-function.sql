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
CREATE OR REPLACE FUNCTION "com.aoapps.security"."Identifier.valueOf" (encoded character(22))
RETURNS "com.aoapps.security"."<Identifier>" AS $$
BEGIN
  IF encoded IS NULL THEN
    RETURN NULL;
  ELSIF length(encoded) != 22 THEN
    RAISE EXCEPTION 'encoded length mismatch: expected 22, got %', length(encoded);
  END IF;
  RETURN ROW(
    "com.aoapps.security"."Identifier.decode"(substr(encoded, 1, 11)),
    "com.aoapps.security"."Identifier.decode"(substr(encoded, 12))
  );
END;
$$ LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
RETURNS NULL ON NULL INPUT;

COMMENT ON FUNCTION "com.aoapps.security"."Identifier.valueOf" (character(22)) IS
'Matches method com.aoapps.security.Identifier.valueOf
Matches method com.aoapps.security.Identifier.<init>(String)';
