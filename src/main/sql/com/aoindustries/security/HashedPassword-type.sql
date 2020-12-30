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
CREATE TYPE "com.aoindustries.security"."<HashedPassword>" AS (
	algorithm text,
	salt bytea,
	iterations integer,
	"hash" bytea
);

COMMENT ON TYPE "com.aoindustries.security"."<HashedPassword>" IS
'Row definition for "com.aoindustries.security"."HashedPassword"';

CREATE DOMAIN "com.aoindustries.security"."HashedPassword" AS "com.aoindustries.security"."<HashedPassword>" CHECK (
	VALUE IS NOT DISTINCT FROM NULL
	OR "com.aoindustries.security"."HashedPassword.validate"(VALUE) IS NULL
);

COMMENT ON DOMAIN "com.aoindustries.security"."HashedPassword" IS
'Matches class com.aoindustries.security.HashedPassword';
