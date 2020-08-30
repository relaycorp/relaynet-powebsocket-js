import { derSerializePublicKey, PrivateNodeRegistration } from '@relaycorp/relaynet-core';
import axios, { AxiosInstance } from 'axios';
import { createHash } from 'crypto';
import { Agent as HttpAgent } from 'http';
import { Agent as HttpsAgent } from 'https';
import { ServerError } from './errors';

const DEFAULT_LOCAL_PORT = 276;
const DEFAULT_REMOVE_PORT = 443;

const DEFAULT_LOCAL_TIMEOUT_MS = 3_000;
const DEFAULT_REMOTE_TIMEOUT_MS = 5_000;

const OCTETS_IN_ONE_MIB = 2 ** 20;

export const PNRA_CONTENT_TYPE = 'application/vnd.relaynet.node-registration.authorization';
export const PNR_CONTENT_TYPE = 'application/vnd.relaynet.node-registration.registration';

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
    });
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
    const response = await this.internalAxios.post('/nodes', pnrrSerialized);
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
}

function sha256Hex(plaintext: Buffer): string {
  return createHash('sha256').update(plaintext).digest('hex');
}
