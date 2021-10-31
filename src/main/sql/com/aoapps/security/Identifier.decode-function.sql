/*
 * ao-security - Best-practices security made usable.
 * Copyright (C) 2020, 2021  AO Industries, Inc.
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
CREATE OR REPLACE FUNCTION "com.aoapps.security"."Identifier.decode" (encoded CHARACTER(11))
RETURNS BIGINT AS $$
DECLARE
	"BASE" NUMERIC(20,0) := 57;
	unsigned NUMERIC(20,0);
BEGIN
	IF encoded IS NULL THEN
		RETURN NULL;
	ELSIF length(encoded) != 11 THEN
		RAISE EXCEPTION 'encoded length mismatch: expected 11, got %', length(encoded);
	END IF;
	unsigned :=
		  "com.aoapps.security"."Identifier.getValue"(substr(encoded,  1, 1)) * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE"
		+ "com.aoapps.security"."Identifier.getValue"(substr(encoded,  2, 1)) * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE"
		+ "com.aoapps.security"."Identifier.getValue"(substr(encoded,  3, 1)) * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE"
		+ "com.aoapps.security"."Identifier.getValue"(substr(encoded,  4, 1)) * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE"
		+ "com.aoapps.security"."Identifier.getValue"(substr(encoded,  5, 1)) * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE"
		+ "com.aoapps.security"."Identifier.getValue"(substr(encoded,  6, 1)) * "BASE" * "BASE" * "BASE" * "BASE" * "BASE"
		+ "com.aoapps.security"."Identifier.getValue"(substr(encoded,  7, 1)) * "BASE" * "BASE" * "BASE" * "BASE"
		+ "com.aoapps.security"."Identifier.getValue"(substr(encoded,  8, 1)) * "BASE" * "BASE" * "BASE"
		+ "com.aoapps.security"."Identifier.getValue"(substr(encoded,  9, 1)) * "BASE" * "BASE"
		+ "com.aoapps.security"."Identifier.getValue"(substr(encoded, 10, 1)) * "BASE"
		+ "com.aoapps.security"."Identifier.getValue"(substr(encoded, 11, 1));
	IF unsigned > '9223372036854775807'::NUMERIC(20,0) THEN
		-- Convert back to twos-complement
		RETURN unsigned - '18446744073709551616'::NUMERIC(20,0);
	ELSE
		RETURN unsigned;
	END IF;
END;
$$ LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
RETURNS NULL ON NULL INPUT;

COMMENT ON FUNCTION "com.aoapps.security"."Identifier.decode" (CHARACTER(11)) IS
'Matches method com.aoapps.security.Identifier.decode';
