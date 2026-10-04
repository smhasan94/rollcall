// Validates CSAF 2.0 documents with the official secvisogram validator library
// (@secvisogram/csaf-validator-lib, pinned by package-lock.json): the strict CSAF 2.0 JSON
// schema test and every mandatory test (CSAF 2.0 section 6.1). Optional tests (6.2) are run
// and reported as warnings; they never fail a document.
//
// Usage: node validate.mjs FILE...  (Node 20.6 or later)
// Prints one PASS or FAIL line per file (with each failing test and its errors) and exits 1
// if any file fails, 2 on a usage or read error.

import { readFile } from 'node:fs/promises'
import { register } from 'node:module'

// See resolve-extensionless.mjs: lets Node load the library's CVSS dependency. Registered
// before the library is imported, so the imports below are dynamic.
register('./resolve-extensionless.mjs', import.meta.url)
const lib = '@secvisogram/csaf-validator-lib'
const { default: validateStrict } = await import(`${lib}/validateStrict.js`)
const schemaTests = await import(`${lib}/schemaTests.js`)
const mandatoryTests = await import(`${lib}/mandatoryTests.js`)
const optionalTests = await import(`${lib}/optionalTests.js`)

const files = process.argv.slice(2)
if (files.length === 0) {
  console.error('usage: node validate.mjs FILE...')
  process.exit(2)
}

const required = [schemaTests.csaf_2_0_strict, ...Object.values(mandatoryTests)]
const optional = Object.values(optionalTests)

let failed = false
for (const file of files) {
  let doc
  try {
    doc = JSON.parse(await readFile(file, 'utf8'))
  } catch (e) {
    console.error(`${file}: cannot read: ${e.message}`)
    process.exit(2)
  }
  const result = await validateStrict(required, doc)
  const failures = result.tests.filter((t) => !t.isValid || t.errors.length > 0)
  const warned = (await validateStrict(optional, doc)).tests.filter(
    (t) => t.warnings.length > 0 || t.errors.length > 0
  )
  if (result.isValid && failures.length === 0) {
    const note = warned.length
      ? ` (optional tests with warnings: ${warned.map((t) => t.name).join(', ')})`
      : ''
    console.log(`PASS ${file}: ${required.length} tests${note}`)
  } else {
    failed = true
    console.log(`FAIL ${file}`)
    for (const t of failures) {
      for (const e of t.errors) {
        console.log(`  ${t.name}: ${e.instancePath} ${e.message}`)
      }
      if (t.errors.length === 0) {
        console.log(`  ${t.name}: invalid`)
      }
    }
  }
}
process.exit(failed ? 1 : 0)
