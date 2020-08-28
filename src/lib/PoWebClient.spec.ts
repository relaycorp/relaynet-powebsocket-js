/* tslint:disable:no-let */

import MockAdapter from 'axios-mock-adapter';
import bufferToArray from 'buffer-to-arraybuffer';

import { ServerError } from './errors';
import { PNRA_CONTENT_TYPE, PoWebClient } from './PoWebClient';

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

  describe('preRegister', () => {
    let client: PoWebClient;
    let mockAxios: MockAdapter;
    beforeEach(() => {
      client = PoWebClient.initLocal();
      mockAxios = new MockAdapter(client.internalAxios);
    });

    test('Empty request should be POSTed to /v1/pre-registrations', async () => {
      mockAxios
        .onPost('/pre-registrations')
        .reply(200, null, { 'content-type': PNRA_CONTENT_TYPE });

      await client.preRegister();

      expect(mockAxios.history.post).toHaveLength(1);
      expect(mockAxios.history.post[0].url).toEqual('/pre-registrations');
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
        .reply(statusCode, null, { 'content-type': PNRA_CONTENT_TYPE });

      await expect(client.preRegister()).rejects.toEqual(
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

      const authorizationSerialized = await client.preRegister();

      expect(
        expectedAuthorizationSerialized.equals(Buffer.from(authorizationSerialized)),
      ).toBeTruthy();
    });
  });
});
