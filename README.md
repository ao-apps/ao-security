# [<img src="ao-logo.png" alt="AO Logo" width="35" height="40">](https://github.com/aoindustries) [AO OSS](https://github.com/aoindustries/ao-oss) / [Security](https://github.com/aoindustries/ao-security)

[![project: current stable](https://oss.aoapps.com/ao-badges/project-current-stable.svg)](https://aoindustries.com/life-cycle#project-current-stable)
[![management: production](https://oss.aoapps.com/ao-badges/management-production.svg)](https://aoindustries.com/life-cycle#management-production)
[![packaging: active](https://oss.aoapps.com/ao-badges/packaging-active.svg)](https://aoindustries.com/life-cycle#packaging-active)  
[![java: &gt;= 8](https://oss.aoapps.com/ao-badges/java-8.svg)](https://docs.oracle.com/javase/8/docs/api/)
[![semantic versioning: 2.0.0](https://oss.aoapps.com/ao-badges/semver-2.0.0.svg)](http://semver.org/spec/v2.0.0.html)
[![license: LGPL v3](https://oss.aoapps.com/ao-badges/license-lgpl-3.0.svg)](https://www.gnu.org/licenses/lgpl-3.0)

[![Build](https://github.com/aoindustries/ao-security/workflows/Build/badge.svg?branch=master)](https://github.com/aoindustries/ao-security/actions?query=workflow%3ABuild)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.aoapps/ao-security/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.aoapps/ao-security)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?branch=master&project=com.aoapps%3Aao-security&metric=alert_status)](https://sonarcloud.io/dashboard?branch=master&id=com.aoapps%3Aao-security)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?branch=master&project=com.aoapps%3Aao-security&metric=ncloc)](https://sonarcloud.io/component_measures?branch=master&id=com.aoapps%3Aao-security&metric=ncloc)  
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?branch=master&project=com.aoapps%3Aao-security&metric=reliability_rating)](https://sonarcloud.io/component_measures?branch=master&id=com.aoapps%3Aao-security&metric=Reliability)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?branch=master&project=com.aoapps%3Aao-security&metric=security_rating)](https://sonarcloud.io/component_measures?branch=master&id=com.aoapps%3Aao-security&metric=Security)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?branch=master&project=com.aoapps%3Aao-security&metric=sqale_rating)](https://sonarcloud.io/component_measures?branch=master&id=com.aoapps%3Aao-security&metric=Maintainability)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?branch=master&project=com.aoapps%3Aao-security&metric=coverage)](https://sonarcloud.io/component_measures?branch=master&id=com.aoapps%3Aao-security&metric=Coverage)

Best-practices security made usable.

## Project Links
* [Project Home](https://oss.aoapps.com/security/)
* [Changelog](https://oss.aoapps.com/security/changelog)
* [API Docs](https://oss.aoapps.com/security/apidocs/)
* [Maven Central Repository](https://search.maven.org/artifact/com.aoapps/ao-security)
* [GitHub](https://github.com/aoindustries/ao-security)

## Features
* Implements best-practices password security, made easy:
    * Operations are [length-constant time](https://crackstation.net/hashing-security.htm).
    * Plaintext passwords and keys are proactively and aggressively destroyed.
    * Passwords are salted and key-stretched.
* `Identifier` and `SmallIdentifier` are 128-bit and 64-bit random identifiers:
    * Base-57 textual representation:
        * Uses an unambiguous subset of URL-safe characters.  For example, the letter `B` is
          excluded as potentially ambiguous with the number `8`.
        * The same length as unpadded base-64 (22 and 11 characters, respectively),
          while being completely URL safe.
        * Shorter than padded base-64 (24 and 12 characters, respectively).
* `Password` and `Key` protect the plaintext from all normal access (reflection, `Unsafe`, and other such
  mechanisms are unavoidable).
* `UnprotectedPassword` and `UnprotectedKey` provide access to the password and key, but with
   automatically destroyed copies.
* `HashedPassword` and `HashedKey` contain hashed/encrypted forms of passwords and keys:
    * Are strongly self-validating, including when deserialized.
    * Are intended for long-term persistence, either in textual forms or in the provided SQL composite types.
* Multi-algorithm support, with backward compatibility mechanisms:
    * Allows systems to upgrade crypto while maintaining compatibility.
    * Textual form includes algorithm, iterations, salt, and hash - everything needed for future password
      validation even when default settings upgraded.
    * Algorithm support going back the full twenty years of AO application support, including the likes of
      `crypt`, `MD5`, `SHA-1`, … (don't use these for new passwords, but they are still supported for
      compatibility with ancient password databases).
* Robust, bi-directional, future-proof textual representations of `HashedPassword` and `HashedKey`:
    * To and from `String` in Java allows storage and transmission as simple text.
    * SQL `CAST` are declared for easy conversion of legacy databases to the new composite types,
      including database-level parsing of all supported algorithms (yes, even you, `crypt`).
* API-provided, actively supported default encryption settings:
    * API recommends to re-hash passwords on login when default settings are stronger than those used
      to originally hash the password.  This allows to keep the stored values up-to-date (or
      to prompt the user to change password, depending on needs).
* Java 1.8 implementation:
    * `Password` and `Key` are `AutoCloseable`, to destroy the plaintext via try-with-resources.
    * `Optional` used where a `Password` or `Key` may not be returned.
    * Very lambda-friendly: `Function`, `Consumer`, and `Predicate` all leveraged in the automatic destruction of passwords and keys.
* Small footprint, minimal dependencies - not part of a big monolithic package.
* Compatible [PostgreSQL](https://www.postgresql.org/) implementation:
    * Composite types for `Identifier`, `HashedPassword`, and `HashedKey`.
    * `DOMAIN` type for `SmallIdentifier`.
    * Full set of validation functions.
    * Very thorough validation, matching every detail the Java API.  As an example, the first four bits
      of the salt for `crypt` are verified to be zero, since `crypt` only uses a 12-bit salt.
    * Full set of bi-directional `TEXT` conversions, including `CAST` definitions, which makes for very simple
      legacy password database upgrades.  All it will typically take is:<br>
      `ALTER TABLE … ALTER COLUMN … TYPE "com.aoapps.security"."HashedPassword";`

## Contact Us
For questions or support, please [contact us](https://aoindustries.com/contact):

Email: [support@aoindustries.com](mailto:support@aoindustries.com)  
Phone: [1-800-519-9541](tel:1-800-519-9541)  
Phone: [+1-251-607-9556](tel:+1-251-607-9556)  
Web: https://aoindustries.com/contact
