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
CREATE OR REPLACE FUNCTION "com.aoapps.security"."UnixCrypt.itoa64" (i INTEGER)
RETURNS CHARACTER AS $$
DECLARE
	"ITOA64" CHARACTER[] := '{.,/,0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z,a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z}';
BEGIN
	RETURN "ITOA64"[(i & 63) + 1];
END;
$$ LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
RETURNS NULL ON NULL INPUT;

COMMENT ON FUNCTION "com.aoapps.security"."UnixCrypt.itoa64" (INTEGER) IS
'Gets the character representation of the low-order six bits of the given int.

Matches method com.aoapps.security.UnixCrypt.itoa64';

CREATE OR REPLACE FUNCTION "com.aoapps.security"."UnixCrypt.itoa64" (i BIGINT)
RETURNS CHARACTER AS $$
BEGIN
	RETURN "com.aoapps.security"."UnixCrypt.itoa64"((i & 63)::INTEGER);
END;
$$ LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
RETURNS NULL ON NULL INPUT;

COMMENT ON FUNCTION "com.aoapps.security"."UnixCrypt.itoa64" (BIGINT) IS
'Gets the character representation of the low-order six bits of the given long.

Matches method com.aoapps.security.UnixCrypt.itoa64';
