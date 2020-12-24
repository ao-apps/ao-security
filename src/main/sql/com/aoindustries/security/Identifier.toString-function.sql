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
CREATE OR REPLACE FUNCTION "com.aoindustries.security"."Identifier.toString" (
	hi BIGINT,
	lo BIGINT
)
RETURNS text AS $$
BEGIN
	RETURN
		   "com.aoindustries.security"."SmallIdentifier.toString"(hi)
		|| "com.aoindustries.security"."SmallIdentifier.toString"(lo);
END;
$$ LANGUAGE plpgsql -- TODO: Language SQL?
IMMUTABLE
RETURNS NULL ON NULL INPUT;

COMMENT ON FUNCTION "com.aoindustries.security"."Identifier.toString" (BIGINT, BIGINT) IS
'Matches method com.aoindustries.security.Identifier.toString';

CREATE OR REPLACE FUNCTION "com.aoindustries.security"."Identifier.toString" (
	this "com.aoindustries.security"."Identifier"
)
RETURNS text AS $$
BEGIN
	RETURN "com.aoindustries.security"."Identifier.toString"(this.hi, this.lo);
END;
$$ LANGUAGE plpgsql -- TODO: Language SQL?
IMMUTABLE
RETURNS NULL ON NULL INPUT;

COMMENT ON FUNCTION "com.aoindustries.security"."Identifier.toString" ("com.aoindustries.security"."Identifier") IS
'Matches method com.aoindustries.security.Identifier.toString';
