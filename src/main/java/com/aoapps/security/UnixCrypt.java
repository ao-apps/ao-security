package com.aoapps.security;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * @deprecated  This is not secure anymore.  We will be removing in a future major version update.  If you still require
 *              this type of encryption, please use {@link org.apache.commons.codec.digest.UnixCrypt}.
 */
@Deprecated // Java 9: (forRemoval = true)
public abstract class UnixCrypt {

  // (mostly) Standard DES Tables from Tom Truscott

  /**
   * initial permutation.
   */
  private static final byte[] IP = {
      58, 50, 42, 34, 26, 18, 10,  2,
      60, 52, 44, 36, 28, 20, 12,  4,
      62, 54, 46, 38, 30, 22, 14,  6,
      64, 56, 48, 40, 32, 24, 16,  8,
      57, 49, 41, 33, 25, 17,  9,  1,
      59, 51, 43, 35, 27, 19, 11,  3,
      61, 53, 45, 37, 29, 21, 13,  5,
      63, 55, 47, 39, 31, 23, 15,  7};

  // The final permutation is the inverse of IP - no table is necessary

  /**
   * expansion operation.
   */
  private static final byte[] ExpandTr = {
      32,  1,  2,  3,  4,  5,
      4,  5,  6,  7,  8,  9,
      8,  9, 10, 11, 12, 13,
      12, 13, 14, 15, 16, 17,
      16, 17, 18, 19, 20, 21,
      20, 21, 22, 23, 24, 25,
      24, 25, 26, 27, 28, 29,
      28, 29, 30, 31, 32,  1};

  /**
   * permuted choice table 1.
   */
  private static final byte[] PC1 = {
      57, 49, 41, 33, 25, 17,  9,
      1, 58, 50, 42, 34, 26, 18,
      10,  2, 59, 51, 43, 35, 27,
      19, 11,  3, 60, 52, 44, 36,

      63, 55, 47, 39, 31, 23, 15,
      7, 62, 54, 46, 38, 30, 22,
      14,  6, 61, 53, 45, 37, 29,
      21, 13,  5, 28, 20, 12,  4};

  /**
   * PC1 rotation schedule.
   */
  private static final byte[] Rotates = {
      1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

  /**
   * permuted choice table 2.
   */
  private static final byte[] PC2 = {
      9, 18,    14, 17, 11, 24,  1,  5,
      22, 25,     3, 28, 15,  6, 21, 10,
      35, 38,    23, 19, 12,  4, 26,  8,
      43, 54,    16,  7, 27, 20, 13,  2,

      0,  0,    41, 52, 31, 37, 47, 55,
      0,  0,    30, 40, 51, 45, 33, 48,
      0,  0,    44, 49, 39, 56, 34, 53,
      0,  0,    46, 42, 50, 36, 29, 32};

  /**
   * 48->32 bit substitution tables.
   */
  private static final byte[][] S = {
      // S[1]
      {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
          0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
          4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
          15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13},
      // S[2]
      {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
          3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
          0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
          13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9},
      // S[3]
      {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
          13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
          13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
          1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12},
      // S[4]
      {7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
          13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
          10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
          3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14},
      // S[5]
      {2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
          14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
          4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
          11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3},
      // S[6]
      {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
          10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
          9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
          4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13},
      // S[7]
      {4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
          13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
          1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
          6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12},
      // S[8]
      {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
          1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
          7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
          2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}};

  /**
   * 32-bit permutation function.
   */
  private static final byte[] P32Tr = {
      16,  7, 20, 21,
      29, 12, 28, 17,
      1, 15, 23, 26,
      5, 18, 31, 10,
      2,  8, 24, 14,
      32, 27,  3,  9,
      19, 13, 30,  6,
      22, 11,  4, 25};

  /**
   * compressed/interleaved permutation.
   */
  private static final byte[] CIFP = {
      1,  2,  3,  4,   17, 18, 19, 20,
      5,  6,  7,  8,   21, 22, 23, 24,
      9, 10, 11, 12,   25, 26, 27, 28,
      13, 14, 15, 16,   29, 30, 31, 32,

      33, 34, 35, 36,   49, 50, 51, 52,
      37, 38, 39, 40,   53, 54, 55, 56,
      41, 42, 43, 44,   57, 58, 59, 60,
      45, 46, 47, 48,   61, 62, 63, 64};

  /**
   * 0..63 => ascii-64.
   */
  private static final char[] ITOA64 =
      "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".toCharArray();

  // =====  Tables that are initialized at run time  ====================

  /**
   * (ascii-64 - ' ') => 0..63.
   */
  private static final byte[] A64TOI = new byte[128 - ' '];

  /**
   * Initial key schedule permutation.
   */
  private static final long[][] PC1ROT = new long[16][16];

  /**
   * Subsequent key schedule rotation permutations.
   */
  private static final long[][][] PC2ROT = new long[2][16][16];

  /**
   * Initial permutation/expansion table.
   */
  private static final long[][] IE3264 = new long[8][16];

  /**
   * Table that combines the S, P, and E operations.
   */
  private static final long[][] SPE = new long[8][64];

  /**
   * compressed/interleaved => final permutation table.
   */
  private static final long[][] CF6464 = new long[16][16];


  // ====================================

  static {
    final byte[] perm = new byte[64];
    final byte[] temp = new byte[64];

    // inverse table.
    for (int i = 0; i < A64TOI.length; i++) {
      A64TOI[i] = -1;
    }
    for (int i = 0; i < 64; i++) {
      A64TOI[ITOA64[i] - ' '] = (byte) i;
    }

    // PC1ROT - bit reverse, then PC1, then Rotate, then PC2
    for (int i = 0; i < 64; i++) {
      perm[i] = 0;
    }
    for (int i = 0; i < 64; i++) {
      int k;
      if ((k = PC2[i]) == 0) {
        continue;
      }
      k += Rotates[0] - 1;
      if ((k % 28) < Rotates[0]) {
        k -= 28;
      }
      k = PC1[k];
      if (k > 0) {
        k--;
        k = (k | 0x07) - (k & 0x07);
        k++;
      }
      perm[i] = (byte) k;
    }
    initPerm(PC1ROT, perm, 8);

    // PC2ROT - PC2 inverse, then Rotate, then PC2
    for (int j = 0; j < 2; j++) {
      int k;
      for (int i = 0; i < 64; i++) {
        perm[i] = temp[i] = 0;
      }
      for (int i = 0; i < 64; i++) {
        if ((k = PC2[i]) == 0) {
          continue;
        }
        temp[k - 1] = (byte) (i + 1);
      }
      for (int i = 0; i < 64; i++) {
        if ((k = PC2[i]) == 0) {
          continue;
        }
        k += j;
        if ((k % 28) <= j) {
          k -= 28;
        }
        perm[i] = temp[k];
      }

      initPerm(PC2ROT[j], perm, 8);
    }

    // Bit reverse, intial permupation, expantion
    for (int i = 0; i < 8; i++) {
      for (int j = 0; j < 8; j++) {
        int k = (j < 2) ? 0 : IP[ExpandTr[i * 6 + j - 2] - 1];
        if (k > 32) {
          k -= 32;
        } else if (k > 0) {
          k--;
        }
        if (k > 0) {
          k--;
          k = (k | 0x07) - (k & 0x07);
          k++;
        }
        perm[i * 8 + j] = (byte) k;
      }
    }

    initPerm(IE3264, perm, 8);

    // Compression, final permutation, bit reverse
    for (int i = 0; i < 64; i++) {
      int k = IP[CIFP[i] - 1];
      if (k > 0) {
        k--;
        k = (k | 0x07) - (k & 0x07);
        k++;
      }
      perm[k - 1] = (byte) (i + 1);
    }

    initPerm(CF6464, perm, 8);

    // SPE table
    for (int i = 0; i < 48; i++) {
      perm[i] = P32Tr[ExpandTr[i] - 1];
    }
    for (int t = 0; t < 8; t++) {
      for (int j = 0; j < 64; j++) {
        int k = ((j & 0x01) << 5) | (((j >> 1) & 0x01) << 3)
            | (((j >> 2) & 0x01) << 2) | (((j >> 3) & 0x01) << 1)
            | ((j >> 4) & 0x01) | (((j >> 5) & 0x01) << 4);
        k = S[t][k];
        k = ((k >> 3) & 0x01) | (((k >> 2) & 0x01) << 1)
            | (((k >> 1) & 0x01) << 2) | ((k & 0x01) << 3);
        for (int i = 0; i < 32; i++) {
          temp[i] = 0;
        }
        for (int i = 0; i < 4; i++) {
          temp[4 * t + i] = (byte) ((k >> i) & 0x01);
        }
        long kk = 0;
        for (int i = 24; --i >= 0; ) {
          kk = (kk << 1)
              | ((long) temp[perm[i] - 1]) << 32
              | ((long) temp[perm[i + 24] - 1]);
        }

        SPE[t][j] = toSixBit(kk);
      }
    }
  }

  /**
   * You can't call the constructor.
   */
  @SuppressFBWarnings("CT_CONSTRUCTOR_THROW")
  private UnixCrypt() {
    throw new AssertionError();
  }

  /**
   * Gets the character representation of the low-order six bits of the given int.
   *
   * @see  #a64toi(char)
   */
  // Matches src/main/sql/com/aoapps/security/UnixCrypt.itoa64-function.sql
  static char itoa64(int i) {
    assert 0x3f == (ITOA64.length - 1);
    return ITOA64[i & 0x3f];
  }

  /**
   * Gets the character representation of the low-order six bits of the given long.
   *
   * @see  #a64toi(char)
   */
  // Matches src/main/sql/com/aoapps/security/UnixCrypt.itoa64-function.sql
  static char itoa64(long i) {
    return itoa64((int) i);
  }

  /**
   * Gets the numeric value represented by the given character.
   *
   * @throws  IllegalArgumentException  when the given character is not used to represent any value
   *
   * @see  #itoa64(int)
   * @see  #itoa64(long)
   */
  // Matches src/main/sql/com/aoapps/security/UnixCrypt.a64toi-function.sql
  static int a64toi(char c) {
    int index = c - ' ';
    byte i;
    if (
        (index < 0 || index >= A64TOI.length)
            || (i = A64TOI[index]) == -1
    ) {
      throw new IllegalArgumentException("crypt: Unexpected character: " + c);
    }
    assert i == (i & 0x3f);
    return i;
  }

  /**
   * @deprecated  This is not secure anymore.
   *              Please use {@link org.apache.commons.codec.digest.UnixCrypt#crypt(java.lang.String)}
   */
  @Deprecated // Java 9: (forRemoval = true)
  public static String crypt(String plaintext) {
    return crypt(
        plaintext,
        new String(new char[]{
            itoa64(Identifier.secureRandom.nextInt(64)),
            itoa64(Identifier.secureRandom.nextInt(64))
        })
    );
  }

  /**
   * Encrypts String into crypt (Unix) code.
   *
   * @param key the key to be encrypted
   * @param setting the salt to be used
   *
   * @return the encrypted String
   *
   * @deprecated  This is not secure anymore.
   *              Please use {@link org.apache.commons.codec.digest.UnixCrypt#crypt(java.lang.String, java.lang.String)}
   */
  @Deprecated // Java 9: (forRemoval = true)
  public static String crypt(String key, String setting) {
    long constdatablock = 0L; // encryption constant
    char[] cryptresult = new char[13]; // encrypted result
    long keyword = 0L;
    int keylen = key.length();

    for (int i = 0; i < 8; i++) {
      keyword = (keyword << 8) | ((i < keylen) ? 2 * key.charAt(i) : 0);
    }

    long[] ks = desSetkey(keyword);

    int salt = 0;
    for (int i = 2; --i >= 0; ) {
      char c = (i < setting.length()) ? setting.charAt(i) : '.';
      cryptresult[i] = c;
      salt = (salt << 6) | a64toi(c);
    }

    long rsltblock = desCipher(constdatablock, salt, 25, ks);

    cryptresult[12] = itoa64(rsltblock << 2);
    rsltblock >>= 4;
    for (int i = 12; --i >= 2; ) {
      cryptresult[i] = itoa64(rsltblock);
      rsltblock >>= 6;
    }

    return new String(cryptresult);
  }

  /**
   * Performs the crypt, returning the long representation.
   */
  @Deprecated // Java 9: (forRemoval = true)
  static long cryptImpl(String key, int salt) {
    long constdatablock = 0L; // encryption constant
    long keyword = 0L;
    int keylen = key.length();

    for (int i = 0; i < 8; i++) {
      keyword = (keyword << 8) | ((i < keylen) ? 2 * key.charAt(i) : 0);
    }

    long[] ks = desSetkey(keyword);

    return desCipher(constdatablock, salt, 25, ks);
  }

  /**
   * Returns the DES encrypted code of the given word with the specified
   * environment.
   */
  private static long desCipher(long in, int salt, int numIter, long[] ks) {
    salt = toSixBit(salt);
    long l = in;
    long r = l;
    l &= 0x5555555555555555L;
    r = (r & 0xaaaaaaaa00000000L) | ((r >> 1) & 0x0000000055555555L);
    l = (((l << 1) | (l << 32)) & 0xffffffff00000000L)
        | ((r | (r >> 32)) & 0x00000000ffffffffL);

    l = perm3264((int) (l >> 32), IE3264);
    r = perm3264((int) (l & 0xffffffff), IE3264);

    while (--numIter >= 0) {
      for (int loopCount = 0; loopCount < 8; loopCount++) {
        long kp = ks[(loopCount << 1)];
        long k = ((r >> 32) ^ r) & salt & 0xffffffffL;
        k |= k << 32;
        long b = k ^ r ^ kp;

        l ^= SPE[0][(int) ((b >> 58) & 0x3f)] ^ SPE[1][(int) ((b >> 50) & 0x3f)]
            ^ SPE[2][(int) ((b >> 42) & 0x3f)] ^ SPE[3][(int) ((b >> 34) & 0x3f)]
            ^ SPE[4][(int) ((b >> 26) & 0x3f)] ^ SPE[5][(int) ((b >> 18) & 0x3f)]
            ^ SPE[6][(int) ((b >> 10) & 0x3f)] ^ SPE[7][(int) ((b >> 2) & 0x3f)];

        kp = ks[(loopCount << 1) + 1];
        k = ((l >> 32) ^ l) & salt & 0xffffffffL;
        k |= k << 32;
        b = k ^ l ^ kp;

        r ^= SPE[0][(int) ((b >> 58) & 0x3f)] ^ SPE[1][(int) ((b >> 50) & 0x3f)]
            ^ SPE[2][(int) ((b >> 42) & 0x3f)] ^ SPE[3][(int) ((b >> 34) & 0x3f)]
            ^ SPE[4][(int) ((b >> 26) & 0x3f)] ^ SPE[5][(int) ((b >> 18) & 0x3f)]
            ^ SPE[6][(int) ((b >> 10) & 0x3f)] ^ SPE[7][(int) ((b >> 2) & 0x3f)];
      }
      // swap L and R
      l ^= r;
      r ^= l;
      l ^= r;
    }
    l = (((l >> 35) & 0x0f0f0f0fL) | (((l & 0xffffffff) << 1) & 0xf0f0f0f0L)) << 32
        | (((r >> 35) & 0x0f0f0f0fL) | (((r & 0xffffffff) << 1) & 0xf0f0f0f0L));

    l = perm6464(l, CF6464);

    return l;
  }

  /**
   * Returns the key schedule for the given key.
   */
  private static long[] desSetkey(long keyword) {
    long k = perm6464(keyword, PC1ROT);
    long[] ks = new long[16];
    ks[0] = k & ~0x0303030300000000L;

    for (int i = 1; i < 16; i++) {
      ks[i] = k;
      k = perm6464(k, PC2ROT[Rotates[i] - 1]);

      ks[i] = k & ~0x0303030300000000L;
    }
    return ks;
  }

  /**
   * Initializes the given permutation table with the mapping table.
   */
  private static void initPerm(long[][] perm, byte[] p, int charsOut) {
    for (int k = 0; k < charsOut * 8; k++) {
      int l = p[k] - 1;
      if (l < 0) {
        continue;
      }
      int i = l >> 2;
      l = 1 << (l & 0x03);
      for (int j = 0; j < 16; j++) {
        int s = (k & 0x07) + ((7 - (k >> 3)) << 3);
        if ((j & l) != 0x00) {
          perm[i][j] |= 1L << s;
        }
      }
    }
  }

  /**
   * Returns the permutation of the given 32-bit code with
   * the specified permutataion table.
   */
  private static long perm3264(int c, long[][]p) {
    long out = 0L;
    for (int i = 4; --i >= 0; ) {
      int t = 0x00ff & c;
      c >>= 8;
      long tp = p[i << 1][t & 0x0f];
      out |= tp;
      tp = p[(i << 1) + 1][t >> 4];
      out |= tp;
    }
    return out;
  }

  /**
   * Returns the permutation of the given 64-bit code with
   * the specified permutataion table.
   */
  private static long perm6464(long c, long[][]p) {
    long out = 0L;
    for (int i = 8; --i >= 0; ) {
      int t = (int) (0x00ff & c);
      c >>= 8;
      long tp = p[i << 1][t & 0x0f];
      out |= tp;
      tp = p[(i << 1) + 1][t >> 4];
      out |= tp;
    }
    return out;
  }

  /**
   * Returns the transposed and split code of a 24-bit code
   * into a 4-byte code, each having 6 bits.
   */
  private static int toSixBit(int num) {
    return ((num << 26) & 0xfc000000) | ((num << 12) & 0xfc0000)
        | ((num >> 2) & 0xfc00) | ((num >> 16) & 0xfc);
  }

  /**
   * Returns the transposed and split code of two 24-bit code
   * into two 4-byte code, each having 6 bits.
   */
  private static long toSixBit(long num) {
    return ((num << 26) & 0xfc000000fc000000L) | ((num << 12) & 0xfc000000fc0000L)
        | ((num >> 2) & 0xfc000000fc00L) | ((num >> 16) & 0xfc000000fcL);
  }

  /**
   * @deprecated  This is not secure anymore.
   *              Please use {@link org.apache.commons.codec.digest.UnixCrypt}
   */
  @Deprecated // Java 9: (forRemoval = true)
  @SuppressWarnings("UseOfSystemOutOrSystemErr")
  public static void main(String[] args) {
    if (args.length == 1) {
      System.out.println(crypt(args[0]));
    } else if (args.length == 2) {
      System.out.println(crypt(args[0], args[1]));
    } else {
      System.err.println("usage: " + UnixCrypt.class.getName() + " password [salt]");
      System.exit(1);
    }
  }
}
