import {
  derSerializePublicKey,
  DETACHED_SIGNATURE_TYPES,
  PrivateNodeRegistration,
  Signer,
} from '@relaycorp/relaynet-core';
import { CertificationPath, generateCertificationPath } from '@relaycorp/relaynet-testing';
import MockAdapter from 'axios-mock-adapter';
import bufferToArray from 'buffer-to-arraybuffer';
import { createHash } from 'crypto';

import { ParcelDeliveryError, RefusedParcelError, ServerError } from './errors';
import {
  PARCEL_CONTENT_TYPE,
  PNR_CONTENT_TYPE,
  PNRA_CONTENT_TYPE,
  PNRR_CONTENT_TYPE,
  PoWebClient,
} from './PoWebClient';

let certificationPath: CertificationPath;
beforeAll(async () => {
  certificationPath = await generateCertificationPath();
});

describe('PoWebClient', () => {
  describe('Common Axios instance defaults', () => {
    test('responseType should be ArrayBuffer', () => {
      const client = PoWebClient.initLocal();

      expect(client.internalAxios.defaults.responseType).toEqual('arraybuffer');
    });

    test('maxContentLength should be 1 MiB', () => {
      const client = PoWebClient.initLocal();

      expect(client.internalAxios.defaults.maxContentLength).toEqual(1048576);
    });

    test('Redirects should be disabled', () => {
      const client = PoWebClient.initLocal();

      expect(client.internalAxios.defaults.maxRedirects).toEqual(0);
    });

    test('Status validation should be disabled', () => {
      const client = PoWebClient.initLocal();

      expect(client.internalAxios.defaults.validateStatus?.(400)).toEqual(true);
    });
  });

  describe('initLocal', () => {
    test('Host name should be the localhost IP address', () => {
      const client = PoWebClient.initLocal();

      expect(client.hostName).toEqual('127.0.0.1');
    });

    test('TLS should not be used', () => {
      const client = PoWebClient.initLocal();

      expect(client.useTLS).toBeFalsy();
    });

    test('Port should default to 276', () => {
      const client = PoWebClient.initLocal();

      expect(client.port).toEqual(276);
    });

    test('Port should be overridable', () => {
      const port = 13276;
      const client = PoWebClient.initLocal(port);

      expect(client.port).toEqual(port);
    });

    test('Base URL should factor in the host name, port and use of TLS', () => {
      const client = PoWebClient.initLocal();

      expect(client.internalAxios.defaults.baseURL).toEqual('http://127.0.0.1:276/v1');
    });

    test('HTTP agent should be configured with Keep-Alive', () => {
      const client = PoWebClient.initLocal();

      expect(client.internalAxios.defaults.httpAgent.keepAlive).toEqual(true);
    });

    test('Default timeout should be 3 seconds', () => {
      const client = PoWebClient.initLocal();

      expect(client.internalAxios.defaults.timeout).toEqual(3_000);
    });
  });

  describe('initRemote', () => {
    const hostName = 'gw.relaycorp.tech';

    test('Specified host name should be honored', () => {
      const client = PoWebClient.initRemote(hostName);

      expect(client.hostName).toEqual(hostName);
    });

    test('TLS should be used', () => {
      const client = PoWebClient.initRemote(hostName);

      expect(client.useTLS).toBeTruthy();
    });

    test('Port should default to 443', () => {
      const client = PoWebClient.initRemote(hostName);

      expect(client.port).toEqual(443);
    });

    test('Port should be overridable', () => {
      const port = 13276;
      const client = PoWebClient.initRemote(hostName, port);

      expect(client.port).toEqual(port);
    });

    test('Base URL should factor in the host name, port and use of TLS', () => {
      const client = PoWebClient.initRemote(hostName);

      expect(client.internalAxios.defaults.baseURL).toEqual(`https://${hostName}:443/v1`);
    });

    test('HTTPS agent should be configured with Keep-Alive', () => {
      const client = PoWebClient.initRemote(hostName);

      expect(client.internalAxios.defaults.httpsAgent.keepAlive).toEqual(true);
    });

    test('Default timeout should be 5 seconds', () => {
      const client = PoWebClient.initRemote(hostName);

      expect(client.internalAxios.defaults.timeout).toEqual(5_000);
    });
  });

  describe('preRegisterNode', () => {
    let client: PoWebClient;
    let mockAxios: MockAdapter;
    beforeEach(() => {
      client = PoWebClient.initLocal();
      mockAxios = new MockAdapter(client.internalAxios);
    });

    let nodePublicKey: CryptoKey;
    beforeAll(async () => {
      nodePublicKey = await certificationPath.privateGateway.certificate.getPublicKey();
    });

    test('Request should be POSTed to /v1/pre-registrations', async () => {
      mockAxios
        .onPost('/pre-registrations')
        .reply(200, null, { 'content-type': PNRA_CONTENT_TYPE });

      await client.preRegisterNode(nodePublicKey);

      expect(mockAxios.history.post).toHaveLength(1);
      expect(mockAxios.history.post[0].url).toEqual('/pre-registrations');
      expect(mockAxios.history.post[0].headers).toHaveProperty('Content-Type', 'text/plain');
    });

    test('Request body should be SHA-256 digest of the node public key', async () => {
      mockAxios
        .onPost('/pre-registrations')
        .reply(200, null, { 'content-type': PNRA_CONTENT_TYPE });

      await client.preRegisterNode(nodePublicKey);

      const publicKeySerialized = await derSerializePublicKey(nodePublicKey);
      const expectedDigest = createHash('sha256').update(publicKeySerialized).digest('hex');
      expect(Buffer.from(mockAxios.history.post[0].data).toString()).toEqual(expectedDigest);
    });

    test('An invalid response content type should be refused', async () => {
      const invalidContentType = 'application/json';
      mockAxios
        .onPost('/pre-registrations')
        .reply(200, null, { 'content-type': invalidContentType });

      await expect(client.preRegisterNode(nodePublicKey)).rejects.toEqual(
        new ServerError(`Server responded with invalid content type (${invalidContentType})`),
      );
    });

    test('20X response status other than 200 should throw an error', async () => {
      const statusCode = 201;
      mockAxios
        .onPost('/pre-registrations')
        .reply(statusCode, null, { 'content-type': PNRA_CONTENT_TYPE });

      await expect(client.preRegisterNode(nodePublicKey)).rejects.toEqual(
        new ServerError(`Unexpected response status (${statusCode})`),
      );
    });

    test('Authorization should be output serialized if status is 200', async () => {
      const expectedAuthorizationSerialized = Buffer.from('the PNRA');
      mockAxios
        .onPost('/pre-registrations')
        .reply(200, bufferToArray(expectedAuthorizationSerialized), {
          'content-type': PNRA_CONTENT_TYPE,
        });

      const authorizationSerialized = await client.preRegisterNode(nodePublicKey);

      expect(
        expectedAuthorizationSerialized.equals(Buffer.from(authorizationSerialized)),
      ).toBeTruthy();
    });
  });

  describe('registerNode', () => {
    let client: PoWebClient;
    let mockAxios: MockAdapter;
    beforeEach(() => {
      client = PoWebClient.initLocal();
      mockAxios = new MockAdapter(client.internalAxios);
    });

    const pnraSerialized = bufferToArray(Buffer.from('the authorization'));

    let expectedRegistration: PrivateNodeRegistration;
    let expectedRegistrationSerialized: ArrayBuffer;
    beforeAll(async () => {
      const tomorrow = new Date();
      tomorrow.setDate(tomorrow.getDate() + 1);

      expectedRegistration = new PrivateNodeRegistration(
        certificationPath.privateGateway.certificate,
        certificationPath.publicGateway.certificate,
      );
      expectedRegistrationSerialized = expectedRegistration.serialize();
    });

    test('PNRA should be POSTed to /v1/nodes', async () => {
      mockAxios
        .onPost('/nodes')
        .reply(200, expectedRegistrationSerialized, { 'content-type': PNR_CONTENT_TYPE });

      await client.registerNode(pnraSerialized);

      expect(mockAxios.history.post).toHaveLength(1);
      expect(mockAxios.history.post[0].url).toEqual('/nodes');
      expect(mockAxios.history.post[0].headers).toHaveProperty('Content-Type', PNRR_CONTENT_TYPE);
      expect(
        Buffer.from(mockAxios.history.post[0].data).equals(Buffer.from(pnraSerialized)),
      ).toBeTruthy();
    });

    test('An invalid response content type should be refused', async () => {
      const invalidContentType = 'text/plain';
      mockAxios
        .onPost('/nodes')
        .reply(200, expectedRegistrationSerialized, { 'content-type': invalidContentType });

      await expect(client.registerNode(pnraSerialized)).rejects.toEqual(
        new ServerError(`Server responded with invalid content type (${invalidContentType})`),
      );
    });

    test('20X response status other than 200 should throw an error', async () => {
      const statusCode = 201;
      mockAxios
        .onPost('/nodes')
        .reply(statusCode, expectedRegistrationSerialized, { 'content-type': PNR_CONTENT_TYPE });

      await expect(client.registerNode(pnraSerialized)).rejects.toEqual(
        new ServerError(`Unexpected response status (${statusCode})`),
      );
    });

    test('Malformed registrations should be refused', async () => {
      const invalidRegistration = Buffer.from('invalid');
      mockAxios
        .onPost('/nodes')
        .reply(200, bufferToArray(invalidRegistration), { 'content-type': PNR_CONTENT_TYPE });

      await expect(client.registerNode(pnraSerialized)).rejects.toMatchObject({
        message: /^Malformed registration received/,
      });
    });

    test('Registration should be output if response status is 200', async () => {
      mockAxios
        .onPost('/nodes')
        .reply(200, expectedRegistrationSerialized, { 'content-type': PNR_CONTENT_TYPE });

      const registration = await client.registerNode(pnraSerialized);

      expect(
        expectedRegistration.privateNodeCertificate.isEqual(registration.privateNodeCertificate),
      ).toBeTruthy();
      expect(
        expectedRegistration.gatewayCertificate.isEqual(registration.gatewayCertificate),
      ).toBeTruthy();
    });
  });

  describe('deliverParcel', () => {
    const parcelSerialized = bufferToArray(Buffer.from('I am a "parcel"'));
    let signer: Signer;
    beforeAll(async () => {
      signer = new Signer(
        certificationPath.privateGateway.certificate,
        certificationPath.privateGateway.privateKey,
      );
    });

    let client: PoWebClient;
    let mockAxios: MockAdapter;
    beforeEach(() => {
      client = PoWebClient.initLocal();
      mockAxios = new MockAdapter(client.internalAxios);
    });

    test('Parcel should be POSTed to /v1/parcels', async () => {
      mockAxios.onPost('/parcels').reply(200, null);

      await client.deliverParcel(parcelSerialized, signer);

      expect(mockAxios.history.post).toHaveLength(1);
      expect(mockAxios.history.post[0].url).toEqual('/parcels');
      expect(mockAxios.history.post[0].headers).toHaveProperty('Content-Type', PARCEL_CONTENT_TYPE);
      expect(
        Buffer.from(mockAxios.history.post[0].data).equals(Buffer.from(parcelSerialized)),
      ).toBeTruthy();
    });

    test('Delivery should be signed with nonce signer', async () => {
      mockAxios.onPost('/parcels').reply(200, null);

      await client.deliverParcel(parcelSerialized, signer);

      const authorizationHeaderValue = mockAxios.history.post[0].headers.authorization;
      expect(authorizationHeaderValue).toBeDefined();
      expect(authorizationHeaderValue).toStartWith('Relaynet-Countersignature ');
      const [, countersignatureBase64] = authorizationHeaderValue.split(' ', 2);
      const countersignature = Buffer.from(countersignatureBase64, 'base64');
      await DETACHED_SIGNATURE_TYPES.PARCEL_DELIVERY.verify(
        bufferToArray(countersignature),
        parcelSerialized,
        [certificationPath.publicGateway.certificate],
      );
    });

    test('HTTP 20X should be regarded a successful delivery', async () => {
      mockAxios.onPost('/parcels').reply(200, null);
      await client.deliverParcel(parcelSerialized, signer);

      mockAxios.onPost('/parcels').reply(299, null);
      await client.deliverParcel(parcelSerialized, signer);
    });

    test('HTTP 403 should throw a RefusedParcelError', async () => {
      mockAxios.onPost('/parcels').reply(403, null);

      const error = await getRejection(client.deliverParcel(parcelSerialized, signer));

      expect(error).toBeInstanceOf(RefusedParcelError);
      expect(error.message).toEqual('Parcel was rejected');
    });

    test('RefusedParcelError should include rejection reason if available', async () => {
      const message = 'Not enough postage';
      mockAxios.onPost('/parcels').reply(403, { message });

      const error = await getRejection(client.deliverParcel(parcelSerialized, signer));

      expect(error).toBeInstanceOf(RefusedParcelError);
      expect(error.message).toEqual(`Parcel was rejected: ${message}`);
    });

    test('HTTP 50X should throw a ServerError', async () => {
      mockAxios.onPost('/parcels').reply(500, null);

      const error = await getRejection(client.deliverParcel(parcelSerialized, signer));

      expect(error).toBeInstanceOf(ServerError);
      expect(error.message).toEqual('Server was unable to get parcel (HTTP 500)');
    });

    test('HTTP responses other than 20X/403/50X should throw errors', async () => {
      mockAxios.onPost('/parcels').reply(400, null);

      const error = await getRejection(client.deliverParcel(parcelSerialized, signer));

      expect(error).toBeInstanceOf(ParcelDeliveryError);
      expect(error.message).toEqual('Could not deliver parcel (HTTP 400)');
    });

    test('Other client exceptions should be propagated', async () => {
      mockAxios.onPost('/parcels').networkError();

      const error = await getRejection(client.deliverParcel(parcelSerialized, signer));

      expect(error).toHaveProperty('isAxiosError', true);
    });
  });
});

async function getRejection(promise: Promise<any>): Promise<Error> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('Expected promise to reject');
}
