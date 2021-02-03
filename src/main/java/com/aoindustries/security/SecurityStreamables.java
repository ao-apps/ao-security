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
	 * Reads a {@link HashedKey}.
	 */
	public static HashedKey readHashedKey(DataInputStream in) throws IOException {
		HashedKey.Algorithm algorithm;
		byte[] hash;
		if(in.readBoolean()) {
			algorithm = HashedKey.Algorithm.findAlgorithm(in.readUTF());
			int hashBytes = Short.toUnsignedInt(in.readShort());
			hash = new byte[hashBytes];
			in.readFully(hash);
		} else {
			algorithm = null;
			hash = null;
		}
		return HashedKey.valueOf(algorithm, hash);
	}

	/**
	 * Reads a possibly-{@code null} {@link HashedKey}.
	 */
	public static HashedKey readNullHashedKey(DataInputStream in) throws IOException {
		return in.readBoolean() ? readHashedKey(in) : null;
	}

	/**
	 * Reads a {@link HashedPassword}.
	 */
	public static HashedPassword readHashedPassword(DataInputStream in) throws IOException {
		HashedPassword.Algorithm algorithm;
		byte[] salt;
		int iterations;
		byte[] hash;
		if(in.readBoolean()) {
			algorithm = HashedPassword.Algorithm.findAlgorithm(in.readUTF());
			int saltBytes = Short.toUnsignedInt(in.readShort());
			salt = new byte[saltBytes];
			in.readFully(salt);
			iterations = in.readInt();
			int hashBytes = Short.toUnsignedInt(in.readShort());
			hash = new byte[hashBytes];
			in.readFully(hash);
		} else {
			algorithm = null;
			salt = null;
			iterations = 0;
			hash = null;
		}
		return HashedPassword.valueOf(algorithm, salt, iterations, hash);
	}

	/**
	 * Reads a possibly-{@code null} {@link HashedPassword}.
	 */
	public static HashedPassword readNullHashedPassword(DataInputStream in) throws IOException {
		return in.readBoolean() ? readHashedPassword(in) : null;
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
	 * Writes a {@link HashedKey}.
	 */
	public static void writeHashedKey(HashedKey hashedKey, DataOutputStream out) throws IOException {
		HashedKey.Algorithm algorithm = hashedKey.getAlgorithm();
		out.writeBoolean(algorithm != null);
		if(algorithm != null) {
			out.writeUTF(algorithm.getAlgorithmName());
			byte[] hash = hashedKey.getHash();
			int hashBytes = hash.length;
			if(hashBytes > 0xFFFF) throw new IOException("length too long for unsigned short: " + hashBytes);
			out.writeShort(hashBytes);
			out.write(hash);
		}
	}

	/**
	 * Writes a possibly-{@code null} {@link HashedKey}.
	 */
	public static void writeNullHashedKey(HashedKey hashedKey, DataOutputStream out) throws IOException {
		out.writeBoolean(hashedKey != null);
		if(hashedKey != null) writeHashedKey(hashedKey, out);
	}

	/**
	 * Writes a {@link HashedPassword}.
	 */
	public static void writeHashedPassword(HashedPassword hashedPassword, DataOutputStream out) throws IOException {
		HashedPassword.Algorithm algorithm = hashedPassword.getAlgorithm();
		out.writeBoolean(algorithm != null);
		if(algorithm != null) {
			out.writeUTF(algorithm.getAlgorithmName());
			byte[] salt = hashedPassword.getSalt();
			int saltBytes = salt.length;
			if(saltBytes > 0xFFFF) throw new IOException("length too long for unsigned short: " + saltBytes);
			out.writeShort(saltBytes);
			out.write(salt);
			out.writeInt(hashedPassword.getIterations());
			byte[] hash = hashedPassword.getHash();
			int hashBytes = hash.length;
			if(hashBytes > 0xFFFF) throw new IOException("length too long for unsigned short: " + hashBytes);
			out.writeShort(hashBytes);
			out.write(hash);
		}
	}

	/**
	 * Writes a possibly-{@code null} {@link HashedPassword}.
	 */
	public static void writeNullHashedPassword(HashedPassword hashedPassword, DataOutputStream out) throws IOException {
		out.writeBoolean(hashedPassword != null);
		if(hashedPassword != null) writeHashedPassword(hashedPassword, out);
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
