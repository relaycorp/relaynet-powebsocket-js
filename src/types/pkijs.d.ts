/* tslint:disable:no-implicit-dependencies no-submodule-imports */

// Workaround for https://github.com/relaycorp/relaynet-core-js/issues/52

declare module 'pkijs' {
  export { default as Certificate } from 'pkijs/src/Certificate';
  export { default as EnvelopedData } from 'pkijs/src/EnvelopedData';
}
