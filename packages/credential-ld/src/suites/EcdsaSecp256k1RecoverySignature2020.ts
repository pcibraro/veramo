import { RequiredAgentMethods, VeramoLdSignature } from '../ld-suites'
import { CredentialPayload, DIDDocument, IAgentContext, IKey, TKeyType } from '@veramo/core'
// import {
//   EcdsaSecp256k1RecoveryMethod2020,
//   EcdsaSecp256k1RecoverySignature2020,
// } from '@transmute/lds-ecdsa-secp256k1-recovery2020'

import * as u8a from 'uint8arrays'
import { asArray, encodeJoseBlob } from '@veramo/utils'

export class VeramoEcdsaSecp256k1RecoverySignature2020 extends VeramoLdSignature {
  getSupportedVerificationTypes(): string[] {
    return ['EcdsaSecp256k1RecoveryMethod2020', "EcdsaSecp256k1VerificationKey2019"]
  }

  getSupportedVeramoKeyTypes(): string[] {
    return ['Secp256k1', 'EcdsaSecp256k1RecoverySignature2020']
  }

  getSigningSuiteInstance(
    key: IKey,
    did: string,
    verifiableMethodId: string,
    context: IAgentContext<RequiredAgentMethods>,
  ): any {
    const controller = did
    const signer = {
      //returns a JWS detached
      sign: async (args: { data: Uint8Array }): Promise<string> => {
        const header = {
          alg: 'ES256K-R',
          b64: false,
          crit: ['b64'],
        }
        const headerString = encodeJoseBlob(header)
        const messageBuffer = u8a.concat([u8a.fromString(`${headerString}.`, 'utf-8'), args.data])
        const messageString = u8a.toString(messageBuffer, 'base64')
        const signature = await context.agent.keyManagerSign({
          keyRef: key.kid,
          algorithm: 'ES256K-R',
          data: messageString,
          encoding: 'base64',
        })
        return `${headerString}..${signature}`
      },
    }

    const suite = new EcdsaSecp256k1RecoverySignature2020({
      // signer,
      key: new EcdsaSecp256k1RecoveryMethod2020({
        publicKeyHex: key.publicKeyHex,
        signer: () => signer,
        type: this.getSupportedVerificationTypes()[0],
        controller,
        id: verifiableMethodId,
      }),
    })

    suite.ensureSuiteContext = ({ document, addSuiteContext }: { document: any, addSuiteContext: boolean }) => {
      document['@context'] = [...asArray(document['@context'] || []), this.getContext()]
    }

    return suite
  }

  getVerificationSuiteInstance(): any {
    return new EcdsaSecp256k1RecoverySignature2020()
  }

  preSigningCredModification(credential: CredentialPayload): void {
    // credential['@context'] = [...asArray(credential['@context'] || []), this.getContext()]
  }

  preDidResolutionModification(didUrl: string, didDoc: DIDDocument): void {
    // did:ethr
    if (didUrl.toLowerCase().startsWith('did:ethr')) {
      // TODO: EcdsaSecp256k1RecoveryMethod2020 does not support blockchainAccountId
      // blockchainAccountId to ethereumAddress
      didDoc.verificationMethod?.forEach((x) => {
        if (x.blockchainAccountId) {
          x.ethereumAddress = x.blockchainAccountId.substring(0, x.blockchainAccountId.lastIndexOf('@'))
        }
      })
    }
  }

  getContext(): string {
    return 'https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld'
  }
}
