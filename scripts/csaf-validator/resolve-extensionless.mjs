// A Node module-resolution hook, registered by validate.mjs.
//
// @secvisogram/csaf-validator-lib's CVSS checks (mandatory test 6.1.9) import
// @pandatix/js-cvss 0.4.4 (its latest release), whose ES modules import their siblings
// without a file extension (`export * from './cvss20'`). Bundlers resolve that; plain Node
// does not. For an import made from inside @pandatix/js-cvss only, this hook retries such a
// relative, extensionless specifier with `.js` appended. It changes nothing else, so every
// test of the library runs unmodified.

const JS_CVSS = '/node_modules/@pandatix/js-cvss/'

export async function resolve(specifier, context, nextResolve) {
  try {
    return await nextResolve(specifier, context)
  } catch (error) {
    const fromJsCvss = (context.parentURL ?? '').includes(JS_CVSS)
    const relative = specifier.startsWith('./') || specifier.startsWith('../')
    const extensionless = !/\.[cm]?js$/.test(specifier)
    if (error?.code === 'ERR_MODULE_NOT_FOUND' && fromJsCvss && relative && extensionless) {
      return nextResolve(`${specifier}.js`, context)
    }
    throw error
  }
}
