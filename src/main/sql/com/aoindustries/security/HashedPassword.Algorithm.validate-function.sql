/*
 * ao-security - Best-practices security made usable.
 * Copyright (C) 2020  AO Industries, Inc.
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
CREATE OR REPLACE FUNCTION "com.aoindustries.security"."HashedPassword.Algorithm.validate" (
	algorithm text,
	salt bytea,
	iterations integer,
	"hash" bytea
)
RETURNS text AS $$
DECLARE
	"saltValid" text;
	"iterationsValid" text;
	"hashValid" text;
BEGIN
	IF (SELECT "name" FROM "com.aoindustries.security"."HashedPassword.Algorithm" WHERE "name" = algorithm) IS NULL THEN
		RETURN 'Unknown algorithm: ' || algorithm;
	ELSIF salt IS NULL THEN
		RETURN 'salt required when have algorithm';
	END IF;
	"saltValid" := "com.aoindustries.security"."HashedPassword.Algorithm.validateSalt"(algorithm, salt);
	IF "saltValid" IS NOT NULL THEN
		RETURN "saltValid";
	END IF;
	"iterationsValid" := "com.aoindustries.security"."HashedPassword.Algorithm.validateIterations"(algorithm, iterations);
	IF "iterationsValid" IS NOT NULL THEN
		RETURN "iterationsValid";
	ELSIF "hash" IS NULL THEN
		RETURN 'hash required when have algorithm';
	END IF;
	"hashValid" := "com.aoindustries.security"."HashedPassword.Algorithm.validateHash"(algorithm, "hash");
	IF "hashValid" IS NOT NULL THEN
		RETURN "hashValid";
	ELSIF algorithm = 'PBKDF2WithHmacSHA1' THEN
		-- Matches method com.aoindustries.security.HashedPassword.Algorithm.PBKDF2WITHHMACSHA1.validate
		-- Performs an additional check that (salt, hash) are either the old sizes or the new, but not a mismatched
		-- combination between them.
		IF (octet_length(salt) = (256 / 8)) != (octet_length("hash") = (256 / 8)) THEN
			RETURN
				algorithm || ': salt length and hash length mismatch: expected either the old default lengths ('
				|| (256 / 8) || ', ' || (256 / 8) || ') or the new lengths ('
				|| (SELECT "saltBytes" FROM "com.aoindustries.security"."HashedPassword.Algorithm" WHERE "name" = algorithm)
				|| ', '
				|| (SELECT "hashBytes" FROM "com.aoindustries.security"."HashedPassword.Algorithm" WHERE "name" = algorithm)
				|| '), got (' || octet_length(salt) || ', ' || octet_length("hash") || ')'
			;
		END IF;
	END IF;
	-- All is OK
	RETURN null;
END;
$$ LANGUAGE plpgsql
IMMUTABLE;
-- PostgreSQL 9.6: PARALLEL SAFE

COMMENT ON FUNCTION "com.aoindustries.security"."HashedPassword.Algorithm.validate" (text, bytea, integer, bytea) IS
'Matches method com.aoindustries.security.HashedPassword.Algorithm.validate
Matches method com.aoindustries.security.HashedPassword.Algorithm.PBKDF2WITHHMACSHA1.validate';
