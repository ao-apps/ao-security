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
CREATE CAST (text AS "com.aoapps.security"."<HashedKey>")
WITH FUNCTION "com.aoapps.security"."HashedKey.valueOf" (text)
AS ASSIGNMENT;

COMMENT ON CAST (text AS "com.aoapps.security"."<HashedKey>") IS
'Matches method com.aoapps.security.HashedKey.valueOf';

CREATE CAST ("com.aoapps.security"."<HashedKey>" AS text)
WITH FUNCTION "com.aoapps.security"."HashedKey.toString" ("com.aoapps.security"."<HashedKey>");

COMMENT ON CAST ("com.aoapps.security"."<HashedKey>" AS text) IS
'Matches method com.aoapps.security.HashedKey.toString';
