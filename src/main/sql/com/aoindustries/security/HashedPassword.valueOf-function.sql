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
CREATE OR REPLACE FUNCTION "com.aoindustries.security"."HashedPassword.valueOf" ("hashedPassword" text)
RETURNS "com.aoindustries.security"."HashedPassword" AS $$
DECLARE
	split text[];
	splitlen integer;
	"algorithmName" text;
	"algorithm" text;
	"hash" bytea;
	hashlen integer;
	"result" "com.aoindustries.security"."HashedPassword";
	"resultValid" text;
BEGIN
	IF "hashedPassword" IS NULL THEN
		"result" := NULL;
	ELSIF "hashedPassword" = '*' THEN
		"result" := ROW(NULL, NULL, 0, NULL);
	ELSIF "hashedPassword" LIKE '$%' THEN
		split := regexp_split_to_array("hashedPassword", '\$');
		splitlen := array_length(split, 1);
		IF splitlen != 5 THEN
			RAISE EXCEPTION 'Unexpected number of parts: expected 5, got %: %', splitlen, "hashedPassword";
		END IF;
		"algorithmName" := split[2];
		algorithm := (SELECT "name" FROM "com.aoindustries.security"."HashedPassword.Algorithm" WHERE lower("name")=lower("algorithmName"));
		IF algorithm IS NULL THEN
			RAISE EXCEPTION 'Unsupported algorithm: %', "algorithmName";
		END IF;
		"result" := ROW(
			"algorithm",
			decode(split[4], 'base64'),
			split[3],
			decode(split[5], 'base64')
		);
	ELSIF length("hashedPassword") = 13 THEN
		RAISE EXCEPTION 'Due to limited (hopefully none at all) use of crypt, parsing will not be implemented in SQL.  Please use the Java API to perform data conversion: %', "hashedPassword";
	ELSIF length("hashedPassword") = 32 THEN
		"result" := ROW('MD5', E''::bytea, 0, decode("hashedPassword", 'hex'));
	ELSE
		"hash" := decode("hashedPassword", 'base64');
		hashlen := octet_length("hash");
		IF hashlen = 20 THEN
			"result" := ROW('SHA-1', E''::bytea, 0, "hash");
		ELSE
			RAISE EXCEPTION 'Unable to guess algorithm by hash length: %', hashlen;
		END IF;
	END IF;
	-- TODO: Don't validate here once is a domain in PostgreSQL 11+
	"resultValid" := "com.aoindustries.security"."HashedPassword.validate"("result");
	IF "resultValid" IS NOT NULL THEN
		RAISE EXCEPTION '%', "resultValid";
	END IF;
	RETURN "result";
END;
$$ LANGUAGE plpgsql
IMMUTABLE
RETURNS NULL ON NULL INPUT;

COMMENT ON FUNCTION "com.aoindustries.security"."HashedPassword.valueOf" (text) IS
'Matches method com.aoindustries.security.HashedPassword.valueOf';
