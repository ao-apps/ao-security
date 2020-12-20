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
package com.aoindustries.security;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * Functions for streaming Security-related objects.
 *
 * @author  AO Industries, Inc.
 */
public class SecurityStreamables {

	private SecurityStreamables() {
	}

	/**
	 * Reads an {@link Identifier}.
	 */
	public static Identifier readIdentifier(DataInputStream in) throws IOException {
		return new Identifier(in.readLong(), in.readLong());
	}

	/**
	 * Reads a possibly-{@code null} {@link Identifier}.
	 */
	public static Identifier readNullIdentifier(DataInputStream in) throws IOException {
		return in.readBoolean() ? readIdentifier(in) : null;
	}

	/**
	 * Reads a {@link SmallIdentifier}.
	 */
	public static SmallIdentifier readSmallIdentifier(DataInputStream in) throws IOException {
		return new SmallIdentifier(in.readLong());
	}

	/**
	 * Reads a possibly-{@code null} {@link Identifier}.
	 */
	public static SmallIdentifier readNullSmallIdentifier(DataInputStream in) throws IOException {
		return in.readBoolean() ? readSmallIdentifier(in) : null;
	}

	/**
	 * Writes an {@link Identifier}.
	 */
	public static void writeIdentifier(Identifier identifier, DataOutputStream out) throws IOException {
		out.writeLong(identifier.getHi());
		out.writeLong(identifier.getLo());
	}

	/**
	 * Writes a possibly-{@code null} {@link Identifier}.
	 */
	public static void writeNullIdentifier(Identifier identifier, DataOutputStream out) throws IOException {
		out.writeBoolean(identifier != null);
		if(identifier != null) writeIdentifier(identifier, out);
	}

	/**
	 * Writes a {@link SmallIdentifier}.
	 */
	public static void writeSmallIdentifier(SmallIdentifier identifier, DataOutputStream out) throws IOException {
		out.writeLong(identifier.getValue());
	}

	/**
	 * Writes a possibly-{@code null} {@link SmallIdentifier}.
	 */
	public static void writeNullSmallIdentifier(SmallIdentifier identifier, DataOutputStream out) throws IOException {
		out.writeBoolean(identifier != null);
		if(identifier != null) writeSmallIdentifier(identifier, out);
	}
}
