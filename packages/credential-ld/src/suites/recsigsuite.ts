/*!
 * Copyright (c) 2020-2021 Digital Bazaar, Inc. All rights reserved.
 */
// import jsigs from '@digitalcredentials/jsonld-signatures';
//
// import { suites } from '@digitalcredentials/jsonld-signatures'
//
// const { LinkedDataSignature } = suites;

import { suites } from "@digitalcredentials/jsonld-signatures";
import { VerificationMethod } from "did-resolver";

import { hash as sha256 } from '@stablelib/sha256'
import { computeAddress } from '@ethersproject/transactions'

// const base58btc = require('@digitalcredentials/base58-universal');
// import {
//   Ed25519VerificationKey2020
// } from '@digitalcredentials/ed25519-verification-key-2020';
import { EcdsaSecp256k1RecoveryMethod2020 } from "./recmethod";
import {
  decodeBase64url,
  extractPublicKeyHex,
  getEthereumAddress,
  recoverSecp256k1PublicKey,
  stringToBytes
} from "@veramo/utils";
// import suiteContext2020 from 'ed25519-signature-2020-context';
// import suiteContext2018 from 'ed25519-signature-2018-context';

// // 'https://w3id.org/security/suites/ed25519-2020/v1'
// const SUITE_CONTEXT_URL = suiteContext2020.constants.CONTEXT_URL;
// // 'https://w3id.org/security/suites/ed25519-2018/v1'
// const SUITE_CONTEXT_URL_2018 = suiteContext2018.constants.CONTEXT_URL;
// // multibase base58-btc header
// const MULTIBASE_BASE58BTC_HEADER = 'z';

import * as u8a from 'uint8arrays'

export type JwsDetachedSigner = {
  sign: (args: { data: Uint8Array }) => Promise<string>
  id: string
}

export type JwsDetachedVerifier = {
  verify: (args: { data: Uint8Array, signature: string }) => Promise<boolean>
  id: string
}

export type EcdsaSecp256k1RecoverySignature2020Proof = {
  jws: string,
  type: "EcdsaSecp256k1RecoverySignature2020",
  [x: string]: any
}

export class EcdsaSecp256k1RecoverySignature2020 extends suites.LinkedDataSignature {
  private requiredKeyTypes: string[];

  /**
   * @param {object} options - Options hashmap.
   *
   * Either a `key` OR at least one of `signer`/`verifier` is required:
   *
   * @param {object} [options.key] - An optional key object (containing an
   *   `id` property, and either `signer` or `verifier`, depending on the
   *   intended operation. Useful for when the application is managing keys
   *   itself (when using a KMS, you never have access to the private key,
   *   and so should use the `signer` param instead).
   * @param {Function} [options.signer] - Signer function that returns an
   *   object with an async sign() method. This is useful when interfacing
   *   with a KMS (since you don't get access to the private key and its
   *   `signer()`, the KMS client gives you only the signer function to use).
   * @param {Function} [options.verifier] - Verifier function that returns
   *   an object with an async `verify()` method. Useful when working with a
   *   KMS-provided verifier function.
   *
   * Advanced optional parameters and overrides:
   *
   * @param {object} [options.proof] - A JSON-LD document with options to use
   *   for the `proof` node (e.g. any other custom fields can be provided here
   *   using a context different from security-v2).
   * @param {string|Date} [options.date] - Signing date to use if not passed.
   * @param {boolean} [options.useNativeCanonize] - Whether to use a native
   *   canonize algorithm.
   */
  constructor({ key, signer, verifier, proof, date, useNativeCanonize }: {
    key?: VerificationMethod, signer?: JwsDetachedSigner, verifier?: JwsDetachedVerifier, proof?: EcdsaSecp256k1RecoverySignature2020Proof, date?: any, useNativeCanonize?: boolean
  } = {}) {
    super({
      type: 'EcdsaSecp256k1RecoverySignature2020', LDKeyClass: EcdsaSecp256k1RecoveryMethod2020,
      contextUrl: 'https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld',
      key, signer, verifier, proof, date, useNativeCanonize
    });
    // Some operations may be performed with EcdsaSecp256k1VerificationKey2019.
    // So, EcdsaSecp256k1RecoveryMethod2020 is recommended, but not strictly required.
    this.requiredKeyTypes = ['EcdsaSecp256k1RecoveryMethod2020', 'EcdsaSecp256k1VerificationKey2019'];
  }

  /**
   * Adds a signature (proofValue) field to the proof object. Called by
   * LinkedDataSignature.createProof().
   *
   * @param {object} options - The options to use.
   * @param {Uint8Array} options.verifyData - Data to be signed (extracted
   *   from document, according to the suite's spec).
   * @param {object} options.proof - Proof object (containing the proofPurpose,
   *   verificationMethod, etc).
   *
   * @returns {Promise<object>} Resolves with the proof containing the signature
   *   value.
   */
  async sign({
               verifyData,
               proof
             }: { verifyData: Uint8Array, proof: any }): Promise<EcdsaSecp256k1RecoverySignature2020Proof> {
    if (!(this.signer && typeof this.signer.sign === 'function')) {
      throw new Error('A signer API has not been specified.');
    }

    proof.jws = await this.signer.sign({ data: verifyData });

    return proof;
  }

  /**
   * Verifies the proof signature against the given data.
   *
   * @param {object} options - The options to use.
   * @param {Uint8Array} options.verifyData - Canonicalized hashed data.
   * @param {object} options.verificationMethod - Key object from DID document.
   * @param {object} options.proof - The proof to be verified.
   *
   * @returns {Promise<boolean>} Resolves with the verification result.
   */
  async verifySignature(args: { verifyData: Uint8Array, verificationMethod: VerificationMethod, proof: EcdsaSecp256k1RecoverySignature2020Proof }): Promise<boolean> {
    const { jws } = args.proof;
    if (!(jws && typeof jws === 'string')) {
      throw new TypeError(
        'invalid_argument: The proof does not include a valid "jws" property.');
    }
    if (jws.indexOf("..") === -1) {
      throw new TypeError("invalid_argument: not a valid rfc7797 jws.");
    }

    const [encodedHeader, encodedSignature] = jws.split("..");
    const header = JSON.parse(decodeBase64url(encodedHeader));
    if (header.alg !== "ES256K-R") {
      throw new TypeError("invalid_argument: JWS alg is not signed with ES256K-R.");
    }
    if (
      header.b64 !== false ||
      !header.crit ||
      !header.crit.length ||
      header.crit[0] !== "b64"
    ) {
      throw new TypeError("invalid_argument: JWS Header is not in rfc7797 format (not detached).");
    }

    let ethereumAddress: string | undefined = undefined
    if (this.requiredKeyTypes.includes(args.verificationMethod.type)) {
      ethereumAddress = getEthereumAddress(args.verificationMethod)
      if (!ethereumAddress) {
        const publicKeyHex = extractPublicKeyHex(args.verificationMethod)
        ethereumAddress = computeAddress(publicKeyHex)
      }
    } else {
      throw new TypeError("invalid_argument: Cannot use this verification method provided to verify this proof, invalid type");
    }

    if (!ethereumAddress) {
      throw new TypeError("invalid_argument: Cannot use this verification method provided to verify this proof, missing publicKey or ethereumAddress");
    }

    const dataToSign = u8a.concat([stringToBytes(encodedHeader + '.'), args.verifyData])
    const dataHash = sha256(dataToSign)

    const recoveredPublicKey = recoverSecp256k1PublicKey(dataHash, u8a.fromString(encodedSignature, "base64url"))
    const recoveredAddress = computeAddress(recoveredPublicKey).toLowerCase()

    return ethereumAddress.toLowerCase() === recoveredAddress.toLowerCase()
  }

  // async assertVerificationMethod({ verificationMethod }) {
  //   let contextUrl;
  //   if (verificationMethod.type === 'Ed25519VerificationKey2020') {
  //     contextUrl = SUITE_CONTEXT_URL;
  //   } else if (verificationMethod.type === 'Ed25519VerificationKey2018') {
  //     contextUrl = SUITE_CONTEXT_URL_2018;
  //   } else {
  //     throw new Error(`Unsupported key type "${verificationMethod.type}".`);
  //   }
  //   if (!_includesContext({
  //     document: verificationMethod, contextUrl
  //   })) {
  //     // For DID Documents, since keys do not have their own contexts,
  //     // the suite context is usually provided by the documentLoader logic
  //     throw new TypeError(
  //       `The verification method (key) must contain "${contextUrl}" context.`
  //     );
  //   }
  //
  //   // ensure verification method has not been revoked
  //   if (verificationMethod.revoked !== undefined) {
  //     throw new Error('The verification method has been revoked.');
  //   }
  // }

  // async getVerificationMethod({ proof, documentLoader }) {
  //   if (this.key) {
  //     // This happens most often during sign() operations. For verify(),
  //     // the expectation is that the verification method will be fetched
  //     // by the documentLoader (below), not provided as a `key` parameter.
  //     return this.key.export({ publicKey: true });
  //   }
  //
  //   let { verificationMethod } = proof;
  //
  //   if (typeof verificationMethod === 'object') {
  //     verificationMethod = verificationMethod.id;
  //   }
  //
  //   if (!verificationMethod) {
  //     throw new Error('No "verificationMethod" found in proof.');
  //   }
  //
  //   const { document } = await documentLoader(verificationMethod);
  //
  //   verificationMethod = typeof document === 'string' ?
  //     JSON.parse(document) : document;
  //
  //   await this.assertVerificationMethod({ verificationMethod });
  //   if (verificationMethod.type === 'Ed25519VerificationKey2018') {
  //     verificationMethod = (await Ed25519VerificationKey2020
  //       .fromEd25519VerificationKey2018({ keyPair: verificationMethod }))
  //       .export({ publicKey: true, includeContext: true });
  //   }
  //   return verificationMethod;
  // }

  // async matchProof({ proof, document, purpose, documentLoader, expansionMap }) {
  //   if (!_includesContext({ document, contextUrl: SUITE_CONTEXT_URL })) {
  //     return false;
  //   }
  //
  //   if (!await super.matchProof({
  //     proof, document, purpose, documentLoader,
  //     expansionMap
  //   })) {
  //     return false;
  //   }
  //   if (!this.key) {
  //     // no key specified, so assume this suite matches and it can be retrieved
  //     return true;
  //   }
  //
  //   const { verificationMethod } = proof;
  //
  //   // only match if the key specified matches the one in the proof
  //   if (typeof verificationMethod === 'object') {
  //     return verificationMethod.id === this.key.id;
  //   }
  //   return verificationMethod === this.key.id;
  // }
}

/**
 * Tests whether a provided JSON-LD document includes a context url in its
 * `@context` property.
 *
 * @param {object} options - Options hashmap.
 * @param {object} options.document - A JSON-LD document.
 * @param {string} options.contextUrl - A context url.
 *
 * @returns {boolean} Returns true if document includes context.
 */
function _includesContext({ document, contextUrl }: { document: any, contextUrl: string}) {
  const context = document['@context'];
  return context === contextUrl ||
    (Array.isArray(context) && context.includes(contextUrl));
}
//
// Ed25519Signature2020.CONTEXT_URL = SUITE_CONTEXT_URL;
// Ed25519Signature2020.CONTEXT = suiteContext2020.contexts.get(SUITE_CONTEXT_URL);
