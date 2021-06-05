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
CREATE TYPE "com.aoapps.security"."<HashedKey>" AS (
	algorithm text,
	"hash" bytea
);

COMMENT ON TYPE "com.aoapps.security"."<HashedKey>" IS
'Row definition for "com.aoapps.security"."HashedKey"';

CREATE DOMAIN "com.aoapps.security"."HashedKey" AS "com.aoapps.security"."<HashedKey>" CHECK (
	VALUE IS NOT DISTINCT FROM NULL
	OR "com.aoapps.security"."HashedKey.validate"(VALUE) IS NULL
);

COMMENT ON DOMAIN "com.aoapps.security"."HashedKey" IS
'Matches class com.aoapps.security.HashedKey';
