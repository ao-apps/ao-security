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
CREATE OR REPLACE FUNCTION "com.aoindustries.security"."HashedKey.valueOf" ("hashedKey" text)
RETURNS "com.aoindustries.security"."HashedKey" AS $$
DECLARE
	split text[];
	splitlen integer;
	"algorithmName" text;
	"algorithm" text;
	"hash" bytea;
	hashlen integer;
	"result" "com.aoindustries.security"."HashedKey";
	"resultValid" text;
BEGIN
	IF "hashedKey" IS NULL THEN
		"result" := NULL;
	ELSIF "hashedKey" = '*' THEN
		"result" := ROW(NULL, NULL);
	ELSIF "hashedKey" LIKE '$%' THEN
		split := regexp_split_to_array("hashedKey", '\$');
		splitlen := array_length(split, 1);
		IF splitlen != 3 THEN
			RAISE EXCEPTION 'Unexpected number of parts: expected 3, got %: %', splitlen, "hashedKey";
		END IF;
		"algorithmName" := split[2];
		algorithm := (SELECT "name" FROM "com.aoindustries.security"."HashedKey.Algorithm" WHERE lower("name")=lower("algorithmName"));
		IF algorithm IS NULL THEN
			RAISE EXCEPTION 'Unsupported algorithm: %', "algorithmName";
		END IF;
		"result" := ROW(
			"algorithm",
			decode(split[3], 'base64')
		);
	ELSIF length("hashedKey") = (128 / 4) THEN
		"result" := ROW('MD5', decode("hashedKey", 'hex'));
	ELSE
		"hash" := decode("hashedKey", 'base64');
		hashlen := octet_length("hash");
		IF hashlen = (160 / 8) THEN
			"result" := ROW('SHA-1', "hash");
		ELSIF hashlen = (224 / 8) THEN
			"result" := ROW('SHA-224', "hash");
		ELSIF hashlen = (256 / 8) THEN
			"result" := ROW('SHA-256', "hash");
		ELSIF hashlen = (384 / 8) THEN
			"result" := ROW('SHA-384', "hash");
		ELSIF hashlen = (512 / 8) THEN
			"result" := ROW('SHA-512', "hash");
		ELSE
			RAISE EXCEPTION 'Unable to guess algorithm by hash length: %', hashlen;
		END IF;
	END IF;
	-- TODO: Don't validate here once is a domain in PostgreSQL 11+
	"resultValid" := "com.aoindustries.security"."HashedKey.validate"("result");
	IF "resultValid" IS NOT NULL THEN
		RAISE EXCEPTION '%', "resultValid";
	END IF;
	RETURN "result";
END;
$$ LANGUAGE plpgsql
IMMUTABLE
-- PostgreSQL 9.6: PARALLEL SAFE
RETURNS NULL ON NULL INPUT;

COMMENT ON FUNCTION "com.aoindustries.security"."HashedKey.valueOf" (text) IS
'Matches method com.aoindustries.security.HashedKey.valueOf';
