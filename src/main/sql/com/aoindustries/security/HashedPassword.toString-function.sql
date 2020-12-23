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
CREATE OR REPLACE FUNCTION "com.aoindustries.security"."HashedPassword.toString" (
	"hashedPassword" "com.aoindustries.security"."HashedPassword"
)
RETURNS text AS $$
BEGIN
	IF "hashedPassword" IS NULL THEN
		RETURN NULL;
	ELSIF "hashedPassword".algorithm IS NULL THEN
		RETURN '*';
	ELSE
		RETURN "com.aoindustries.security"."HashedPassword.Algorithm.toString"(
			"hashedPassword".algorithm,
			"hashedPassword".salt,
			"hashedPassword".iterations,
			"hashedPassword"."hash"
		);
	END IF;
END;
$$ LANGUAGE plpgsql
IMMUTABLE
RETURNS NULL ON NULL INPUT;

COMMENT ON FUNCTION "com.aoindustries.security"."HashedPassword.toString" ("com.aoindustries.security"."HashedPassword") IS
'Matches method com.aoindustries.security.HashedPassword.toString';
