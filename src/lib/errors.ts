// tslint:disable:max-classes-per-file

import { VError } from 'verror';

abstract class PoWebError extends VError {}

export class ServerError extends PoWebError {}
