import {
  derSerializePublicKey,
  generateRSAKeyPair,
  issueEndpointCertificate,
  issueGatewayCertificate,
  PrivateNodeRegistration,
} from '@relaycorp/relaynet-core';
import MockAdapter from 'axios-mock-adapter';
import bufferToArray from 'buffer-to-arraybuffer';
import { createHash } from 'crypto';

import { ServerError } from './errors';
import { PNR_CONTENT_TYPE, PNRA_CONTENT_TYPE, PNRR_CONTENT_TYPE, PoWebClient } from './PoWebClient';

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

      expect(client.internalAxios.defaults.validateStatus).toEqual(null);
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
      const keyPair = await generateRSAKeyPair();
      nodePublicKey = keyPair.publicKey;
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

      const gatewayKeyPair = await generateRSAKeyPair();
      const gatewayCertificate = await issueGatewayCertificate({
        issuerPrivateKey: gatewayKeyPair.privateKey,
        subjectPublicKey: gatewayKeyPair.publicKey,
        validityEndDate: tomorrow,
      });

      const privateNodeKeyPair = await generateRSAKeyPair();
      const privateNodeCertificate = await issueEndpointCertificate({
        issuerCertificate: gatewayCertificate,
        issuerPrivateKey: gatewayKeyPair.privateKey,
        subjectPublicKey: privateNodeKeyPair.publicKey,
        validityEndDate: tomorrow,
      });

      expectedRegistration = new PrivateNodeRegistration(
        privateNodeCertificate,
        gatewayCertificate,
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
    test.todo('Request should be made with HTTP POST');

    test.todo('Endpoint should be the one for parcels');

    test.todo('Request content type should be the appropriate value');

    test.todo('Request body should be the parcel serialized');

    test.todo('Delivery should be signed with nonce signer');

    test.todo('HTTP 20X should be regarded a successful delivery');

    test.todo('HTTP 403 should throw a RefusedParcelException');

    test.todo('Other client exceptions should be propagated');
  });
});
