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
 * along with ao-security.  If not, see <http://www.gnu.org/licenses/>.
 */
CREATE OR REPLACE FUNCTION "com.aoapps.security"."HashedPassword.Algorithm.validateSalt" (
	algorithm text,
	salt bytea
)
RETURNS text AS $$
DECLARE
	expected integer;
BEGIN
	-- Matches method com.aoapps.security.HashedPassword.Algorithm.CRYPT.validateSalt
	IF algorithm = 'crypt' AND (get_byte(salt, 0) & 240) != 0 THEN
		RETURN algorithm || ': salt must be twelve bits only';
	-- Matches method com.aoapps.security.HashedPassword.Algorithm.PBKDF2WITHHMACSHA1.validateSalt
	-- Also allows the 256-bit salt for compatibility with previous versions.
	ELSIF NOT (algorithm = 'PBKDF2WithHmacSHA1' AND octet_length(salt) = (256 / 8)) THEN
		-- Matches method com.aoapps.security.HashedPassword.Algorithm.validateSalt
		expected := (SELECT "saltBytes" FROM "com.aoapps.security"."HashedPassword.Algorithm" WHERE "name" = algorithm);
		IF octet_length(salt) != expected THEN
			RETURN algorithm || ': salt length mismatch: expected ' || expected || ', got ' || octet_length(salt);
		END IF;
	END IF;
	-- All is OK
	RETURN null;
END;
$$ LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE;

COMMENT ON FUNCTION "com.aoapps.security"."HashedPassword.Algorithm.validateSalt" (text, bytea) IS
'Matches method com.aoapps.security.HashedPassword.Algorithm.validateSalt
Matches method com.aoapps.security.HashedPassword.Algorithm.CRYPT.validateSalt
Matches method com.aoapps.security.HashedPassword.Algorithm.PBKDF2WITHHMACSHA1.validateSalt';
