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
CREATE OR REPLACE FUNCTION "com.aoindustries.security"."HashedPassword.valueOf" ("hashedPassword" TEXT)
RETURNS "com.aoindustries.security"."<HashedPassword>" AS $$
DECLARE
	split TEXT[];
	splitlen INTEGER;
	salt INTEGER;
	rsltblock BIGINT;
	salt_hex TEXT;
	rsltblock_hex TEXT;
	"algorithmName" TEXT;
	"algorithm" TEXT;
	"hash" BYTEA;
	hashlen INTEGER;
	"result" "com.aoindustries.security"."<HashedPassword>";
	"resultValid" TEXT;
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
		salt :=
			  ("com.aoindustries.security"."UnixCrypt.a64toi"(substr("hashedPassword", 2, 1)) << 6)
			|  "com.aoindustries.security"."UnixCrypt.a64toi"(substr("hashedPassword", 1, 1));
		rsltblock :=
			  ("com.aoindustries.security"."UnixCrypt.a64toi"(substr("hashedPassword", 3, 1))::BIGINT << 58)
			| ("com.aoindustries.security"."UnixCrypt.a64toi"(substr("hashedPassword", 4, 1))::BIGINT << 52)
			| ("com.aoindustries.security"."UnixCrypt.a64toi"(substr("hashedPassword", 5, 1))::BIGINT << 46)
			| ("com.aoindustries.security"."UnixCrypt.a64toi"(substr("hashedPassword", 6, 1))::BIGINT << 40)
			| ("com.aoindustries.security"."UnixCrypt.a64toi"(substr("hashedPassword", 7, 1))::BIGINT << 34)
			| ("com.aoindustries.security"."UnixCrypt.a64toi"(substr("hashedPassword", 8, 1))::BIGINT << 28)
			| ("com.aoindustries.security"."UnixCrypt.a64toi"(substr("hashedPassword", 9, 1))::BIGINT << 22)
			| ("com.aoindustries.security"."UnixCrypt.a64toi"(substr("hashedPassword",10, 1))::BIGINT << 16)
			| ("com.aoindustries.security"."UnixCrypt.a64toi"(substr("hashedPassword",11, 1))::BIGINT << 10)
			| ("com.aoindustries.security"."UnixCrypt.a64toi"(substr("hashedPassword",12, 1))::BIGINT <<  4)
			| ("com.aoindustries.security"."UnixCrypt.a64toi"(substr("hashedPassword",13, 1))::BIGINT >>  2);
		-- Zero-pad hex to full binary length
		salt_hex := right('000' || to_hex(salt), 4);
		rsltblock_hex := right('000000000000000' || to_hex(rsltblock), 16);
		"result" := ROW(
			'crypt',
			decode(salt_hex, 'hex'),
			0,
			decode(rsltblock_hex, 'hex')
		);
	ELSIF length("hashedPassword") = (128 / 4) THEN
		"result" := ROW('MD5', E''::bytea, 0, decode("hashedPassword", 'hex'));
	ELSE
		"hash" := decode("hashedPassword", 'base64');
		hashlen := octet_length("hash");
		IF hashlen = (160 / 8) THEN
			"result" := ROW('SHA-1', E''::bytea, 0, "hash");
		ELSE
			RAISE EXCEPTION 'Unable to guess algorithm by hash length: %', hashlen;
		END IF;
	END IF;
	"resultValid" := "com.aoindustries.security"."HashedPassword.validate"("result");
	IF "resultValid" IS NOT NULL THEN
		RAISE EXCEPTION '%', "resultValid";
	END IF;
	RETURN "result";
END;
$$ LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
RETURNS NULL ON NULL INPUT;

COMMENT ON FUNCTION "com.aoindustries.security"."HashedPassword.valueOf" (TEXT) IS
'Matches method com.aoindustries.security.HashedPassword.valueOf';
