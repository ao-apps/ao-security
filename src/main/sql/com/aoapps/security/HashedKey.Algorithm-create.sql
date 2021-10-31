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
CREATE TABLE "com.aoapps.security"."HashedKey.Algorithm" (
	"name" text PRIMARY KEY CHECK ("name" NOT LIKE '%$%'),
	secure boolean NOT NULL,
	"keyBytes" smallint NOT NULL CHECK ("keyBytes" >= 0),
	"hashBytes" smallint NOT NULL CHECK ("hashBytes" > 0)
);

INSERT INTO "com.aoapps.security"."HashedKey.Algorithm" VALUES
('MD5',         FALSE, 128 / 8, 128 / 8),
('SHA-1',       FALSE, 128 / 8, 160 / 8),
('SHA-224',     FALSE, 224 / 8, 224 / 8),
('SHA-256',      TRUE, 256 / 8, 256 / 8),
('SHA-384',      TRUE, 384 / 8, 384 / 8),
('SHA-512',      TRUE, 512 / 8, 512 / 8),
('SHA-512/224', FALSE, 224 / 8, 224 / 8),
('SHA-512/256',  TRUE, 256 / 8, 256 / 8),
('SHA3-224',    FALSE, 224 / 8, 224 / 8),
('SHA3-256',     TRUE, 256 / 8, 256 / 8),
('SHA3-384',     TRUE, 384 / 8, 384 / 8),
('SHA3-512',     TRUE, 512 / 8, 512 / 8);

COMMENT ON TABLE "com.aoapps.security"."HashedKey.Algorithm" IS
'Matches enum com.aoapps.security.HashedKey.Algorithm';
