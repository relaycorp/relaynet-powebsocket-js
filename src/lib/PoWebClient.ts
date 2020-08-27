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
    return new PoWebClient('127.0.0.1', port, false);
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
    return new PoWebClient(hostName, port, true);
  }

  private static readonly DEFAULT_LOCAL_PORT = 276;
  private static readonly DEFAULT_REMOVE_PORT = 443;

  constructor(
    public readonly hostName: string,
    public readonly port: number,
    public readonly useTLS: boolean,
  ) {}
}
