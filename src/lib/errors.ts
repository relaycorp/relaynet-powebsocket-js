// tslint:disable:max-classes-per-file

import { VError } from 'verror';

abstract class PoWebError extends VError {}

export class ServerError extends PoWebError {}

export class ParcelDeliveryError extends PoWebError {}

export class RefusedParcelError extends PoWebError {}
