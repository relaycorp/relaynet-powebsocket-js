import axios, { AxiosInstance } from 'axios';
import { Agent as HttpAgent } from 'http';
import { Agent as HttpsAgent } from 'https';
import { ServerError } from './errors';

const DEFAULT_LOCAL_PORT = 276;
const DEFAULT_REMOVE_PORT = 443;

const DEFAULT_LOCAL_TIMEOUT_MS = 3_000;
const DEFAULT_REMOTE_TIMEOUT_MS = 5_000;

const OCTETS_IN_ONE_MIB = 2 ** 20;

export const CRA_CONTENT_TYPE = 'application/vnd.relaynet.cra';

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
   * Request a Client Registration Authorization (CRA)
   *
   * @throws [ServerError] If the server doesn't adhere to the protocol
   */
  public async preRegister(): Promise<ArrayBuffer> {
    const response = await this.internalAxios.post('/pre-registrations');

    if (response.status !== 200) {
      throw new ServerError(`Unexpected response status (${response.status})`);
    }

    const contentType = response.headers['content-type'];
    if (contentType !== CRA_CONTENT_TYPE) {
      throw new ServerError(`Server responded with invalid content type (${contentType})`);
    }

    return response.data;
  }
}
