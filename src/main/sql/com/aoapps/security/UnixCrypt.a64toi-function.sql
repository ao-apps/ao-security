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
CREATE OR REPLACE FUNCTION "com.aoapps.security"."UnixCrypt.a64toi" (c CHARACTER)
RETURNS INTEGER AS $$
DECLARE
	pos integer;
	"ITOA64" TEXT := './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
BEGIN
	IF c IS NULL THEN
		RETURN NULL;
	ELSIF length(c) != 1 THEN
		RAISE EXCEPTION 'c length mismatch: expected 1, got %', length(c);
	END IF;
	pos := position(c in "ITOA64");
	IF pos = 0 THEN
		RAISE EXCEPTION 'crypt: Unexpected character: %', c;
	ELSE
		RETURN pos - 1;
	END IF;
END;
$$ LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
RETURNS NULL ON NULL INPUT;

COMMENT ON FUNCTION "com.aoapps.security"."UnixCrypt.a64toi" (CHARACTER) IS
'Gets the numeric value represented by the given character.

Matches method com.aoapps.security.UnixCrypt.a64toi';
