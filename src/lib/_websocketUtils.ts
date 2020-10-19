import { ServerError } from './errors';

export enum WebSocketCode {
  NORMAL = 1000,
  CANNOT_ACCEPT = 1003,
  NO_STATUS = 1005,
  ABRUPT_CLOSE = 1006,
  VIOLATED_POLICY = 1008,
}

interface CloseFrame {
  readonly code: number;
  readonly reason?: string;
}

const NORMAL_CLOSE_CODES: readonly WebSocketCode[] = [
  WebSocketCode.NORMAL,
  WebSocketCode.NO_STATUS,

  // Workaround for https://github.com/relaycorp/relaynet-poweb-js/issues/41
  WebSocketCode.ABRUPT_CLOSE,
];

export class WebSocketStateManager {
  // tslint:disable-next-line:readonly-keyword
  protected serverCloseFrame: CloseFrame | undefined;

  // tslint:disable-next-line:readonly-keyword
  protected _clientCloseFrame: CloseFrame = { code: WebSocketCode.NORMAL };

  // tslint:disable-next-line:readonly-keyword
  protected clientError: Error | undefined;

  // tslint:disable-next-line:readonly-keyword
  private connectionError: Error | undefined;

  get hasServerClosedConnection(): boolean {
    return !!this.serverCloseFrame;
  }

  get clientCloseFrame(): CloseFrame {
    return this._clientCloseFrame;
  }

  public registerServerClosure(code: number, reason?: string): void {
    // tslint:disable-next-line:no-object-mutation
    this.serverCloseFrame = { code, reason };
  }

  public registerConnectionError(error: Error): void {
    // tslint:disable-next-line:no-object-mutation
    this.connectionError = error;
  }

  public registerServerProtocolViolation(clientError: Error, clientCloseFrame: CloseFrame): void {
    // tslint:disable-next-line:no-object-mutation
    this.clientError = clientError;
    // tslint:disable-next-line:no-object-mutation
    this._clientCloseFrame = clientCloseFrame;
  }

  public throwConnectionErrorIfAny(): void {
    if (this.connectionError) {
      throw new ServerError(this.connectionError, 'Connection error');
    }
  }

  public throwClientErrorIfAny(): void {
    if (this.serverCloseFrame && !NORMAL_CLOSE_CODES.includes(this.serverCloseFrame.code)) {
      throw new ServerError(
        'Server closed connection unexpectedly ' +
          `(code: ${this.serverCloseFrame.code}, reason: ${this.serverCloseFrame.reason})`,
      );
    }

    if (this.clientError) {
      throw this.clientError;
    }
  }
}
