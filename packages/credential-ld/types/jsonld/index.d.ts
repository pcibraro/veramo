declare module '@digitalcredentials/ed25519-signature-2020'
declare module '@digitalcredentials/ed25519-verification-key-2020'
declare module '@digitalcredentials/jsonld'
declare module '@digitalcredentials/vc'
// declare module '@transmute/lds-ecdsa-secp256k1-recovery2020'

declare module '@digitalcredentials/jsonld-signatures' {
  export declare function extendContextLoader(documentLoader: (url: string) => Promise<any>): Promise<any>

  //
  // declare class LinkedDataSignatureDef {
  //   LDKeyClass: object
  //   signer: {
  //     sign: () => Promise<any>
  //   }
  //   constructor({LDKeyClass, signer}): LinkedDataSignatureDef
  //   /**
  //    * @param verifyData {Uint8Array}.
  //    * @param document {object} to be signed.
  //    * @param proof {object}
  //    * @param documentLoader {function}
  //    * @param expansionMap {function}
  //    *
  //    * @returns {Promise<{object}>} the proof containing the signature value.
  //    */
  //   sign: (args: {
  //     verifyData: Uint8Array,
  //     document: object,
  //     proof: object,
  //     documentLoader: any,
  //     expansionMap: any
  //   }) => Promise<object>
  //
  //   /**
  //    * @param verifyData {Uint8Array}.
  //    * @param verificationMethod {object}.
  //    * @param document {object} to be signed.
  //    * @param proof {object}
  //    * @param documentLoader {function}
  //    * @param expansionMap {function}
  //    *
  //    * @returns {Promise<boolean>}
  //    */
  //   verifySignature: (args: {
  //     verifyData: Uint8Array,
  //     verificationMethod: object,
  //     document: object,
  //     proof: object,
  //     documentLoader: any
  //     expansionMap: any
  //   }) => Promise<boolean>
  // }
  //
  export declare const suites: {
    LinkedDataSignature: {
      new({ type, proof, LDKeyClass, date, key, signer, verifier, useNativeCanonize, contextUrl }?: {
        type: string;
        proof?: object;
        LDKeyClass: Function;
        date: any;
        key?: any;
        signer?: {
          sign: Function;
          id: string;
        };
        verifier?: {
          verify: Function;
          id: string;
        };
        useNativeCanonize?: boolean;
        contextUrl: string
      }): LinkedDataSignature
    }
  }

  declare class LinkedDataSignature extends LinkedDataProof {
    /**
     * Parent class from which the various LinkDataSignature suites (such as
     * `Ed25519Signature2020`) inherit.
     * NOTE: Developers are never expected to use this class directly, but to
     * only work with individual suites.
     *
     * @param {object} options - Options hashmap.
     * @param {string} options.type - Suite name, provided by subclass.
     * @typedef LDKeyPair
     * @param {LDKeyPair} LDKeyClass - The crypto-ld key class that this suite
     *   will use to sign/verify signatures. Provided by subclass. Used
     *   during the `verifySignature` operation, to create an instance (containing
     *   a `verifier()` property) of a public key fetched via a `documentLoader`.
     *
     * @param {string} contextUrl - JSON-LD context URL that corresponds to this
     *   signature suite. Provided by subclass. Used for enforcing suite context
     *   during the `sign()` operation.
     *
     * For `sign()` operations, either a `key` OR a `signer` is required.
     * For `verify()` operations, you can pass in a verifier (from KMS), or
     * the public key will be fetched via documentLoader.
     *
     * @param {object} [options.key] - An optional key object (containing an
     *   `id` property, and either `signer` or `verifier`, depending on the
     *   intended operation. Useful for when the application is managing keys
     *   itself (when using a KMS, you never have access to the private key,
     *   and so should use the `signer` param instead).
     *
     * @param {{sign: Function, id: string}} [options.signer] - Signer object
     *   that has two properties: an async `sign()` method, and an `id`. This is
     *   useful when interfacing with a KMS (since you don't get access to the
     *   private key and its `signer`, the KMS client gives you only the signer
     *   object to use).
     *
     * @param {{verify: Function, id: string}} [options.verifier] - Verifier
     *   object that has two properties: an async `verify()` method, and an `id`.
     *   Useful when working with a KMS-provided verifier.
     *
     * Advanced optional parameters and overrides:
     *
     * @param {object} [options.proof] - A JSON-LD document with options to use
     *   for the `proof` node (e.g. any other custom fields can be provided here
     *   using a context different from security-v2). If not provided, this is
     *   constructed during signing.
     * @param {string|Date} [options.date] - Signing date to use (otherwise
     *   defaults to `now()`).
     * @param {boolean} [options.useNativeCanonize] - Whether to use a native
     *   canonize algorithm.
     */
    constructor({ type, proof, LDKeyClass, date, key, signer, verifier, useNativeCanonize, contextUrl }?: {
      type: string;
      proof: object;
      LDKeyClass: Function;
      data: any;
      key: any;
      signer: {
        sign: Function;
        id: string;
      };
      verifier: {
        verify: Function;
        id: string;
      };
      useNativeCanonize?: boolean;
      contextUrl: string
    });

    LDKeyClass: Function;
    contextUrl: string;
    proof: object;
    verificationMethod: string;
    key: any;
    signer: {
      sign: Function;
      id: string;
    };
    verifier: {
      verify: Function;
      id: string;
    };
    date: Date;
    useNativeCanonize: boolean;

    /**
     * @param document {object} to be signed.
     * @param purpose {ProofPurpose}
     * @param documentLoader {function}
     * @param expansionMap {function}
     *
     * @returns {Promise<object>} Resolves with the created proof object.
     */
    updateProof({ proof }: object): Promise<object>;

    canonize(input: any, { documentLoader, expansionMap, skipExpansion }: {
      documentLoader: any;
      expansionMap: any;
      skipExpansion: any;
    }): Promise<any>;

    canonizeProof(proof: any, { document, documentLoader, expansionMap }: {
      document: any;
      documentLoader: any;
      expansionMap: any;
    }): Promise<any>;

    /**
     * @param document {object} to be signed/verified.
     * @param proof {object}
     * @param documentLoader {function}
     * @param expansionMap {function}
     *
     * @returns {Promise<{Uint8Array}>}.
     */
    createVerifyData({ document, proof, documentLoader, expansionMap }: object): Promise<{
      Uint8Array;
    }>;

    /**
     * @param document {object} to be signed.
     * @param proof {object}
     * @param documentLoader {function}
     */
    getVerificationMethod({ proof, documentLoader }: object): Promise<any>;

    /**
     * @param args.verifyData {Uint8Array}.
     * @param args.document {object} to be signed.
     * @param args.proof {object}
     * @param args.documentLoader {function}
     * @param args.expansionMap {function}
     *
     * @returns {Promise<{object}>} the proof containing the signature value.
     */
    sign(args: {
      verifyData: Uint8Array,
      document: object,
      proof: object,
      documentLoader: any,
      expansionMap: any
    }): Promise<object>

    /**
     * @param verifyData {Uint8Array}.
     * @param verificationMethod {object}.
     * @param document {object} to be signed.
     * @param proof {object}
     * @param documentLoader {function}
     * @param expansionMap {function}
     *
     * @returns {Promise<boolean>}
     */
    verifySignature(args: {
      verifyData: Uint8Array,
      verificationMethod: VerificationMethod,
      proof: any,
      documentLoader: any,
      expansionMap: any
    }): Promise<boolean>;

    /**
     * Ensures the document to be signed contains the required signature suite
     * specific `@context`, by either adding it (if `addSuiteContext` is true),
     * or throwing an error if it's missing.
     *
     * @param {object} options - Options hashmap.
     * @param {object} options.document - JSON-LD document to be signed.
     * @param {boolean} options.addSuiteContext - Add suite context?
     */
    ensureSuiteContext({ document, addSuiteContext }: {
      document: object;
      addSuiteContext: boolean;
    }): void;
  }

  import LinkedDataProof = require("@digitalcredentials/jsonld-signatures/lib/suites/LinkedDataProof");
}

declare module "*.json" {
  const content: any;
  export default content;
}
