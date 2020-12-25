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
CREATE CAST (text AS "com.aoindustries.security"."HashedKey")
WITH FUNCTION "com.aoindustries.security"."HashedKey.valueOf" (text)
AS ASSIGNMENT;

COMMENT ON CAST (text AS "com.aoindustries.security"."HashedKey") IS
'Matches method com.aoindustries.security.HashedKey.valueOf';

CREATE CAST ("com.aoindustries.security"."HashedKey" AS text)
WITH FUNCTION "com.aoindustries.security"."HashedKey.toString" ("com.aoindustries.security"."HashedKey");

COMMENT ON CAST ("com.aoindustries.security"."HashedKey" AS text) IS
'Matches method com.aoindustries.security.HashedKey.toString';
