import axios, { AxiosInstance } from 'axios';
import { Agent as HttpAgent } from 'http';
import { Agent as HttpsAgent } from 'https';

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
  public static initLocal(port: number = PoWebClient.DEFAULT_LOCAL_PORT): PoWebClient {
    return new PoWebClient('127.0.0.1', port, false, PoWebClient.DEFAULT_LOCAL_TIMEOUT_MS);
  }

  /**
   * Connect to a public gateway from a private gateway via TLS.
   *
   * @param hostName The IP address or domain for the PoWeb server
   * @param port The port for the PoWeb server
   */
  public static initRemote(
    hostName: string,
    port: number = PoWebClient.DEFAULT_REMOVE_PORT,
  ): PoWebClient {
    return new PoWebClient(hostName, port, true, PoWebClient.DEFAULT_REMOTE_TIMEOUT_MS);
  }

  private static readonly DEFAULT_LOCAL_PORT = 276;
  private static readonly DEFAULT_REMOVE_PORT = 443;

  private static readonly DEFAULT_LOCAL_TIMEOUT_MS = 3_000;
  private static readonly DEFAULT_REMOTE_TIMEOUT_MS = 5_000;

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
    const agent = useTLS ? new HttpsAgent({ keepAlive: true }) : new HttpAgent({ keepAlive: true });
    this.internalAxios = axios.create({
      baseURL: `${httpSchema}://${hostName}:${port}/v1`,
      [agentName]: agent,
      timeout: timeoutMs,
    });
  }
}
