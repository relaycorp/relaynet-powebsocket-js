/* tslint:disable:no-let */

import MockAdapter from 'axios-mock-adapter';
import bufferToArray from 'buffer-to-arraybuffer';

import { ServerError } from './errors';
import { CRA_CONTENT_TYPE, PoWebClient } from './PoWebClient';

describe('PoWebClient', () => {
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

  describe('preRegister', () => {
    let client: PoWebClient;
    let mockAxios: MockAdapter;
    beforeEach(() => {
      client = PoWebClient.initLocal();
      mockAxios = new MockAdapter(client.internalAxios);
    });

    const defaultReply: readonly [number, any, {}] = [
      200,
      null,
      { 'content-type': CRA_CONTENT_TYPE },
    ];

    test('Request method should be POST', async () => {
      mockAxios.onPost('/pre-registrations').reply(...defaultReply);

      await client.preRegister();

      expect(mockAxios.history.post).toHaveLength(1);
    });

    test('Endpoint should be /v1/pre-registrations', async () => {
      mockAxios.onPost('/pre-registrations').reply(...defaultReply);

      await client.preRegister();

      expect(mockAxios.history.post[0].url).toEqual('/pre-registrations');
    });

    test('Request body should be empty', async () => {
      mockAxios.onPost('/pre-registrations').reply(...defaultReply);

      await client.preRegister();

      expect(mockAxios.history.post[0].data).toBeUndefined();
    });

    test('An invalid response content type should be refused', async () => {
      const invalidContentType = 'application/json';
      mockAxios
        .onPost('/pre-registrations')
        .reply(200, null, { 'content-type': invalidContentType });

      await expect(client.preRegister()).rejects.toEqual(
        new ServerError(`Server responded with invalid content type (${invalidContentType})`),
      );
    });

    test('20X response status other than 200 should throw an error', async () => {
      const statusCode = 201;
      mockAxios
        .onPost('/pre-registrations')
        .reply(statusCode, null, { 'content-type': CRA_CONTENT_TYPE });

      await expect(client.preRegister()).rejects.toEqual(
        new ServerError(`Unexpected response status (${statusCode})`),
      );
    });

    test('CRA should be output serialized if status is 200', async () => {
      const dummyCRABuffer = Buffer.from('the CRA');
      const dummyCRAArrayBuffer = bufferToArray(dummyCRABuffer);
      mockAxios
        .onPost('/pre-registrations')
        .reply(200, dummyCRAArrayBuffer, { 'content-type': CRA_CONTENT_TYPE });

      const cra = await client.preRegister();

      expect(dummyCRABuffer.equals(Buffer.from(cra))).toBeTruthy();
    });
  });
});
