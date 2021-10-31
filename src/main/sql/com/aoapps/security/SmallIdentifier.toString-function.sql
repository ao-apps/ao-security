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
CREATE OR REPLACE FUNCTION "com.aoapps.security"."SmallIdentifier.toString.positive_truncate_divide" (
	dividend NUMERIC(20,0),
	divisor NUMERIC(20,0)
)
RETURNS NUMERIC(20,0) AS $$
BEGIN
	RETURN ((dividend - mod(dividend, divisor)) / divisor)::NUMERIC(20,0);
END;
$$ LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
RETURNS NULL ON NULL INPUT;

COMMENT ON FUNCTION "com.aoapps.security"."SmallIdentifier.toString.positive_truncate_divide" (
	NUMERIC(20,0),
	NUMERIC(20,0)
) IS
'PostgreSQL seems to have a rounding-up behavior (sometimes) on numeric division.
For example:
    select 8442361102747480762::numeric(20,0) / 57::numeric(20,0);
    Yields 148111598293815452 but should be 148111598293815451
This works around this issue by first subtracting the modulus.
This only works on positive values for this specific purpose.';

CREATE OR REPLACE FUNCTION "com.aoapps.security"."SmallIdentifier.toString" (
	this "com.aoapps.security"."SmallIdentifier"
)
RETURNS text AS $$
DECLARE
	"BASE" NUMERIC(20,0) := 57;
	num NUMERIC(20,0) := this;
BEGIN
	IF num IS NULL THEN
		RETURN NULL;
	ELSIF num < 0 THEN
		num := num + '18446744073709551616'::numeric(20,0);
	END IF;
	RETURN
		   "com.aoapps.security"."Identifier.getCharacter"("com.aoapps.security"."SmallIdentifier.toString.positive_truncate_divide"(num, ("BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE")))
		|| "com.aoapps.security"."Identifier.getCharacter"("com.aoapps.security"."SmallIdentifier.toString.positive_truncate_divide"(num, ("BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE")))
		|| "com.aoapps.security"."Identifier.getCharacter"("com.aoapps.security"."SmallIdentifier.toString.positive_truncate_divide"(num, ("BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE")))
		|| "com.aoapps.security"."Identifier.getCharacter"("com.aoapps.security"."SmallIdentifier.toString.positive_truncate_divide"(num, ("BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE")))
		|| "com.aoapps.security"."Identifier.getCharacter"("com.aoapps.security"."SmallIdentifier.toString.positive_truncate_divide"(num, ("BASE" * "BASE" * "BASE" * "BASE" * "BASE" * "BASE")))
		|| "com.aoapps.security"."Identifier.getCharacter"("com.aoapps.security"."SmallIdentifier.toString.positive_truncate_divide"(num, ("BASE" * "BASE" * "BASE" * "BASE" * "BASE")))
		|| "com.aoapps.security"."Identifier.getCharacter"("com.aoapps.security"."SmallIdentifier.toString.positive_truncate_divide"(num, ("BASE" * "BASE" * "BASE" * "BASE")))
		|| "com.aoapps.security"."Identifier.getCharacter"("com.aoapps.security"."SmallIdentifier.toString.positive_truncate_divide"(num, ("BASE" * "BASE" * "BASE")))
		|| "com.aoapps.security"."Identifier.getCharacter"("com.aoapps.security"."SmallIdentifier.toString.positive_truncate_divide"(num, ("BASE" * "BASE")))
		|| "com.aoapps.security"."Identifier.getCharacter"("com.aoapps.security"."SmallIdentifier.toString.positive_truncate_divide"(num, "BASE"))
		|| "com.aoapps.security"."Identifier.getCharacter"(num);
END;
$$ LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
RETURNS NULL ON NULL INPUT;

COMMENT ON FUNCTION "com.aoapps.security"."SmallIdentifier.toString" ("com.aoapps.security"."SmallIdentifier") IS
'Matches method com.aoapps.security.SmallIdentifier.toString';
