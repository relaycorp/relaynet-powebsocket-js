import { ServerError } from './errors';

export enum WebSocketCode {
  NORMAL = 1000,
  CANNOT_ACCEPT = 1003,
  VIOLATED_POLICY = 1008,
}

interface CloseFrame {
  readonly code: number;
  readonly reason?: string;
}

export class WebSocketStateManager {
  // tslint:disable-next-line:readonly-keyword
  protected serverCloseFrame: CloseFrame | undefined;

  // tslint:disable-next-line:readonly-keyword
  protected _clientCloseFrame: CloseFrame = { code: WebSocketCode.NORMAL };

  // tslint:disable-next-line:readonly-keyword
  protected clientError: Error | undefined;

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

  public registerServerProtocolViolation(clientError: Error, clientCloseFrame: CloseFrame): void {
    // tslint:disable-next-line:no-object-mutation
    this.clientError = clientError;
    // tslint:disable-next-line:no-object-mutation
    this._clientCloseFrame = clientCloseFrame;
  }

  public throwConnectionErrorIfAny(): void {
    if (this.serverCloseFrame && this.serverCloseFrame.code !== WebSocketCode.NORMAL) {
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
