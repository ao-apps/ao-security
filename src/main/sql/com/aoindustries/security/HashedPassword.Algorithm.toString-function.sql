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
CREATE OR REPLACE FUNCTION "com.aoindustries.security"."HashedPassword.Algorithm.toString" (
	algorithm text,
	salt bytea,
	iterations integer,
	"hash" bytea
)
RETURNS text AS $$
DECLARE
	"argsValid" text;
	"ITOA64" text[] := '{.,/,0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z,a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z}';
BEGIN
	"argsValid" := "com.aoindustries.security"."HashedPassword.Algorithm.validate"(algorithm, salt, iterations, "hash");
	IF "argsValid" IS NOT NULL THEN
		RAISE EXCEPTION '%', "argsValid";
	ELSIF algorithm = 'crypt' THEN
		-- Matches method com.aoindustries.security.HashedPassword.Algorithm.CRYPT.toString
		RETURN
			-- Salt
			"ITOA64"[(  get_byte(salt, 1)       & 63                                   ) + 1] ||
			"ITOA64"[(((get_byte(salt, 0) << 2) & 60) | ((get_byte(salt, 1) >> 6) &  3)) + 1] ||
			-- Hash
			"ITOA64"[(((get_byte(hash, 0) >> 2) & 63)                                  ) + 1] ||
			"ITOA64"[(((get_byte(hash, 0) << 4) & 48) | ((get_byte(hash, 1) >> 4) & 15)) + 1] ||
			"ITOA64"[(((get_byte(hash, 1) << 2) & 60) | ((get_byte(hash, 2) >> 6) &  3)) + 1] ||
			"ITOA64"[(  get_byte(hash, 2)       & 63                                   ) + 1] ||
			"ITOA64"[(((get_byte(hash, 3) >> 2) & 63)                                  ) + 1] ||
			"ITOA64"[(((get_byte(hash, 3) << 4) & 48) | ((get_byte(hash, 4) >> 4) & 15)) + 1] ||
			"ITOA64"[(((get_byte(hash, 4) << 2) & 60) | ((get_byte(hash, 5) >> 6) &  3)) + 1] ||
			"ITOA64"[(  get_byte(hash, 5)       & 63                                   ) + 1] ||
			"ITOA64"[(((get_byte(hash, 6) >> 2) & 63)                                  ) + 1] ||
			"ITOA64"[(((get_byte(hash, 6) << 4) & 48) | ((get_byte(hash, 7) >> 4) & 15)) + 1] ||
			"ITOA64"[(((get_byte(hash, 7) << 2) & 60)                                  ) + 1];
	ELSIF algorithm = 'MD5' THEN
		-- Matches method com.aoindustries.security.HashedPassword.Algorithm.MD5.toString
		-- MD5 is represented as hex characters of hash only.
		RETURN replace(encode("hash", 'hex'), E'\n', '');
	ELSIF algorithm = 'SHA-1' THEN
		-- Matches method com.aoindustries.security.HashedPassword.Algorithm.SHA_1.toString
		-- SHA-1 is base-64 only, to match historical usage.
		RETURN replace(encode("hash", 'base64'), E'\n', '');
	ELSE
		-- Matches method com.aoindustries.security.HashedPassword.Algorithm.toString
		RETURN '$' || algorithm
			|| '$' || iterations
			|| '$' || replace(encode(salt, 'base64'), E'\n', '')
			|| '$' || replace(encode("hash", 'base64'), E'\n', '');
	END IF;
END;
$$ LANGUAGE plpgsql
IMMUTABLE;

COMMENT ON FUNCTION "com.aoindustries.security"."HashedPassword.Algorithm.toString" (text, bytea, integer, bytea) IS
'Matches method com.aoindustries.security.HashedPassword.Algorithm.toString
Matches method com.aoindustries.security.HashedPassword.Algorithm.CRYPT.toString
Matches method com.aoindustries.security.HashedPassword.Algorithm.MD5.toString
Matches method com.aoindustries.security.HashedPassword.Algorithm.SHA_1.toString';
