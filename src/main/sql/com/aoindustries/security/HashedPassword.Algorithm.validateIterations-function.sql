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
CREATE OR REPLACE FUNCTION "com.aoindustries.security"."HashedPassword.Algorithm.validateIterations" (
	algorithm text,
	iterations integer
)
RETURNS text AS $$
DECLARE
	"_minimumIterations" integer;
	"_maximumIterations" integer;
BEGIN
	"_minimumIterations" := (SELECT "minimumIterations" FROM "com.aoindustries.security"."HashedPassword.Algorithm" WHERE "name" = algorithm);
	IF iterations < "_minimumIterations" THEN
		RETURN algorithm || ': iterations < minimumIterations: ' || iterations || ' < ' || "_minimumIterations";
	END IF;
	"_maximumIterations" := (SELECT "maximumIterations" FROM "com.aoindustries.security"."HashedPassword.Algorithm" WHERE "name" = algorithm);
	IF "_maximumIterations" IS NOT NULL And iterations > "_maximumIterations" THEN
		RETURN algorithm || ': iterations > maximumIterations: ' || iterations || ' > ' || "_maximumIterations";
	END IF;
	-- All is OK
	RETURN null;
END;
$$ LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE;

COMMENT ON FUNCTION "com.aoindustries.security"."HashedPassword.Algorithm.validateIterations" (text, integer) IS
'Matches method com.aoindustries.security.HashedPassword.Algorithm.validateIterations';
