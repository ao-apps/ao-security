/*
 * ao-security - Best-practices security made usable.
 * Copyright (C) 2020, 2021, 2022  AO Industries, Inc.
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
CREATE TYPE "com.aoapps.security"."<Identifier>" AS (
  hi bigint,
  lo bigint
);

COMMENT ON TYPE "com.aoapps.security"."<Identifier>" IS
'Row definition for "com.aoapps.security"."Identifier"';

CREATE DOMAIN "com.aoapps.security"."Identifier" AS "com.aoapps.security"."<Identifier>" CHECK (
  VALUE IS NOT DISTINCT FROM NULL
  OR "com.aoapps.security"."Identifier.validate"(VALUE) IS NULL
);

COMMENT ON DOMAIN "com.aoapps.security"."Identifier" IS
'Matches class com.aoapps.security.Identifier';
