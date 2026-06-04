import assert from 'assert';
import { DOMAIN_RE, isValidHostname } from './validation.js';

function runSmokeTests() {
    console.log("Running validation.js smoke tests...");

    // 1. Test Unicode/IDN Domains for DOMAIN_RE
    const validDomains = [
        'việt.vn',
        '日本語.jp',
        'google.com',
        'github.io',
        'xn--vit-5kz.vn',
        'xn--e1afmkfd.xn--p1ai', // пример.рф in punycode
        'sub.example.co.uk',
        'localhost',
        'chinhphu.vn'
    ];

    const invalidDomains = [
        '',
        '   ',
        'google..com',
        '-google.com',
        'google.com-',
        '123.456', // Too short to be IP, not a valid domain
    ];

    let passed = 0;
    let failed = 0;

    for (const d of validDomains) {
        if (DOMAIN_RE.test(d)) {
            passed++;
        } else {
            console.error(`[FAIL] DOMAIN_RE should match: ${d}`);
            failed++;
        }
    }

    for (const d of invalidDomains) {
        if (!DOMAIN_RE.test(d)) {
            passed++;
        } else {
            console.error(`[FAIL] DOMAIN_RE should reject: ${d}`);
            failed++;
        }
    }

    // 2. Test isValidHostname (which strips protocols)
    const testHostnames = [
        { input: 'http://việt.vn', expect: true },
        { input: 'https://日本語.jp/path?q=1', expect: true },
        { input: '1.1.1.1', expect: true },
        { input: '2001:4860:4860::8888', expect: true },
        { input: 'http://', expect: false },
        { input: 'just-a-string', expect: false }
    ];

    for (const t of testHostnames) {
        if (isValidHostname(t.input) === t.expect) {
            passed++;
        } else {
            console.error(`[FAIL] isValidHostname('${t.input}') should be ${t.expect}`);
            failed++;
        }
    }

    console.log(`\nResults: ${passed} passed, ${failed} failed.`);
    if (failed > 0) {
        process.exit(1);
    }
}

runSmokeTests();
