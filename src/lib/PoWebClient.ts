import {
  derSerializePublicKey,
  DETACHED_SIGNATURE_TYPES,
  HandshakeChallenge,
  HandshakeResponse,
  ParcelCollection,
  PrivateNodeRegistration,
  Signer,
} from '@relaycorp/relaynet-core';
import axios, { AxiosInstance } from 'axios';
import bufferToArray from 'buffer-to-arraybuffer';
import { createHash } from 'crypto';
import { Agent as HttpAgent } from 'http';
import { Agent as HttpsAgent } from 'https';
import { resolve as resolveURL } from 'url';
import WebSocket from 'ws';

import {
  InvalidHandshakeChallengeError,
  ParcelDeliveryError,
  RefusedParcelError,
  ServerError,
} from './errors';
import { StreamingMode } from './StreamingMode';
import { WebSocketCode } from './WebSocketCode';

const DEFAULT_LOCAL_PORT = 276;
const DEFAULT_REMOVE_PORT = 443;

const DEFAULT_LOCAL_TIMEOUT_MS = 3_000;
const DEFAULT_REMOTE_TIMEOUT_MS = 5_000;

const OCTETS_IN_ONE_MIB = 2 ** 20;

export const PNRA_CONTENT_TYPE = 'application/vnd.relaynet.node-registration.authorization';
export const PNRR_CONTENT_TYPE = 'application/vnd.relaynet.node-registration.request';
export const PNR_CONTENT_TYPE = 'application/vnd.relaynet.node-registration.registration';
export const PARCEL_CONTENT_TYPE = 'application/vnd.relaynet.parcel';

/**
 * PoWeb client.
 */
export class PoWebClient {
  /**
   * Connect to a private gateway from a private endpoint.
   *
   * @param port The port for the PoWeb server
   *
   * TLS won't be used.
   */
  public static initLocal(port: number = DEFAULT_LOCAL_PORT): PoWebClient {
    return new PoWebClient('127.0.0.1', port, false, DEFAULT_LOCAL_TIMEOUT_MS);
  }

  /**
   * Connect to a public gateway from a private gateway via TLS.
   *
   * @param hostName The IP address or domain for the PoWeb server
   * @param port The port for the PoWeb server
   */
  public static initRemote(hostName: string, port: number = DEFAULT_REMOVE_PORT): PoWebClient {
    return new PoWebClient(hostName, port, true, DEFAULT_REMOTE_TIMEOUT_MS);
  }

  private static requireResponseStatusToEqual(actualStatus: number, expectedStatus: number): void {
    if (actualStatus !== expectedStatus) {
      throw new ServerError(`Unexpected response status (${actualStatus})`);
    }
  }

  private static requireResponseContentTypeToEqual(
    actualContentType: string,
    expectedContentType: string,
  ): void {
    if (actualContentType !== expectedContentType) {
      throw new ServerError(`Server responded with invalid content type (${actualContentType})`);
    }
  }

  /**
   * @internal
   */
  public readonly internalAxios: AxiosInstance;

  private readonly wsBaseURL: string;

  protected constructor(
    public readonly hostName: string,
    public readonly port: number,
    public readonly useTLS: boolean,
    timeoutMs: number,
  ) {
    const httpSchema = useTLS ? 'https' : 'http';
    const agentName = useTLS ? 'httpsAgent' : 'httpAgent';
    const agentClass = useTLS ? HttpsAgent : HttpAgent;
    this.internalAxios = axios.create({
      [agentName]: new agentClass({ keepAlive: true }),
      baseURL: `${httpSchema}://${hostName}:${port}/v1`,
      maxContentLength: OCTETS_IN_ONE_MIB,
      maxRedirects: 0,
      responseType: 'arraybuffer',
      timeout: timeoutMs,
      validateStatus: () => true,
    });

    const wsSchema = useTLS ? 'wss' : 'ws';
    this.wsBaseURL = `${wsSchema}://${hostName}:${port}/v1/`;
  }

  /**
   * Request a Private Node Registration Authorization (PNRA).
   *
   * @param nodePublicKey The public key of the private node requesting authorization
   * @return The PNRA serialized
   * @throws [ServerError] If the server doesn't adhere to the protocol
   */
  public async preRegisterNode(nodePublicKey: CryptoKey): Promise<ArrayBuffer> {
    const nodePublicKeySerialized = await derSerializePublicKey(nodePublicKey);
    const nodePublicKeyDigest = sha256Hex(nodePublicKeySerialized);
    const response = await this.internalAxios.post('/pre-registrations', nodePublicKeyDigest, {
      headers: { 'content-type': 'text/plain' },
    });

    PoWebClient.requireResponseStatusToEqual(response.status, 200);
    PoWebClient.requireResponseContentTypeToEqual(
      response.headers['content-type'],
      PNRA_CONTENT_TYPE,
    );

    return response.data;
  }

  /**
   * Register a private node.
   *
   * @param pnrrSerialized The Private Node Registration Request
   */
  public async registerNode(pnrrSerialized: ArrayBuffer): Promise<PrivateNodeRegistration> {
    const response = await this.internalAxios.post('/nodes', pnrrSerialized, {
      headers: { 'content-type': PNRR_CONTENT_TYPE },
    });
    PoWebClient.requireResponseStatusToEqual(response.status, 200);
    PoWebClient.requireResponseContentTypeToEqual(
      response.headers['content-type'],
      PNR_CONTENT_TYPE,
    );

    try {
      return PrivateNodeRegistration.deserialize(response.data);
    } catch (exc) {
      throw new ServerError(exc, 'Malformed registration received');
    }
  }

  /**
   * Send a parcel to the gateway.
   *
   * @param parcelSerialized
   * @param signer
   */
  public async deliverParcel(parcelSerialized: ArrayBuffer, signer: Signer): Promise<void> {
    const signature = await signer.sign(parcelSerialized, DETACHED_SIGNATURE_TYPES.PARCEL_DELIVERY);
    const countersignatureBase64 = Buffer.from(signature).toString('base64');
    const authorizationHeaderValue = `Relaynet-Countersignature ${countersignatureBase64}`;
    const response = await this.internalAxios.post('/parcels', parcelSerialized, {
      headers: { authorization: authorizationHeaderValue, 'content-type': PARCEL_CONTENT_TYPE },
    });

    if (response.status < 300) {
      return;
    }

    const errorMessage = response.data?.message;
    if (response.status === 403) {
      throw new RefusedParcelError(
        errorMessage ? `Parcel was rejected: ${errorMessage}` : 'Parcel was rejected',
      );
    }
    if (500 <= response.status) {
      throw new ServerError(`Server was unable to get parcel (HTTP ${response.status})`);
    }
    throw new ParcelDeliveryError(`Could not deliver parcel (HTTP ${response.status})`);
  }

  public async *collectParcels(
    nonceSigners: readonly Signer[],
    _streamingMode: StreamingMode = StreamingMode.KEEP_ALIVE,
  ): AsyncIterable<ParcelCollection> {
    const wsURL = resolveURL(this.wsBaseURL, 'parcel-collection');
    const ws = new WebSocket(wsURL);
    await new Promise((resolve, reject) => {
      ws.on('close', () => {
        reject(
          new InvalidHandshakeChallengeError(
            'Server closed the connection before/during the handshake',
          ),
        );
      });

      ws.once('message', async (message) => {
        let challenge: HandshakeChallenge;
        try {
          challenge = HandshakeChallenge.deserialize(bufferToArray(message));
        } catch (error) {
          ws.close(WebSocketCode.VIOLATED_POLICY, 'Malformed handshake challenge');
          reject(
            new InvalidHandshakeChallengeError(
              error,
              'Server sent a malformed handshake challenge',
            ),
          );
        }

        const nonceSignatures = await Promise.all(
          nonceSigners.map((s) => s.sign(challenge.nonce, DETACHED_SIGNATURE_TYPES.NONCE)),
        );
        const response = new HandshakeResponse(nonceSignatures);
        ws.send(Buffer.from(response.serialize()));
        resolve();
      });
    });
  }
}

function sha256Hex(plaintext: Buffer): string {
  return createHash('sha256').update(plaintext).digest('hex');
}
