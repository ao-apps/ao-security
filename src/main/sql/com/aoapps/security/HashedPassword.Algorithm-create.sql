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
CREATE TABLE "com.aoapps.security"."HashedPassword.Algorithm" (
	"name" text PRIMARY KEY CHECK ("name" NOT LIKE '%$%'),
	secure boolean NOT NULL,
	"saltBytes" smallint NOT NULL CHECK ("saltBytes" >= 0),
	"minimumIterations" integer NOT NULL CHECK ("minimumIterations" >= 0),
	"maximumIterations" integer,
	"recommendedIterations" integer NOT NULL,
	"hashBytes" smallint NOT NULL CHECK ("hashBytes" > 0),
	CHECK (
		CASE WHEN "minimumIterations" = 0 THEN
			"maximumIterations" = 0
			AND "recommendedIterations" = 0
		ELSE
			("maximumIterations" IS NULL OR "maximumIterations" > 0)
			AND "recommendedIterations" > 0
		END
	)
);

INSERT INTO "com.aoapps.security"."HashedPassword.Algorithm" VALUES
('crypt',                FALSE,       2, 0,    0,     0,  64 / 8),
('MD5',                  FALSE,       0, 0,    0,     0, 128 / 8),
('SHA-1',                FALSE,       0, 0,    0,     0, 160 / 8),
('PBKDF2WithHmacSHA1',   FALSE, 128 / 8, 1, NULL, 85000, 160 / 8),
('PBKDF2WithHmacSHA224', FALSE, 128 / 8, 1, NULL, 50000, 224 / 8),
('PBKDF2WithHmacSHA256',  TRUE, 128 / 8, 1, NULL, 50000, 256 / 8),
('PBKDF2WithHmacSHA384',  TRUE, 128 / 8, 1, NULL, 37000, 384 / 8),
('PBKDF2WithHmacSHA512',  TRUE, 128 / 8, 1, NULL, 37000, 512 / 8);

COMMENT ON TABLE "com.aoapps.security"."HashedPassword.Algorithm" IS
'Matches enum com.aoapps.security.HashedPassword.Algorithm';
