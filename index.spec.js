const { ContentSecurityPolicyParser } = require('./index');

const defaultHeader = "default-src 'self'; base-uri 'self'; block-all-mixed-content; font-src 'self' https: data:; frame-ancestors 'self'; img-src 'self' data: www.example.com; object-src 'none'; script-src 'self' 'sha256-2yQBTLGLI1sDcBILfj/o6b5ufMv6CEwPYOk3RZI/WjE=' 'sha256-GeDavzSZ8O71Jggf/pQkKbt52dfZkrdNMQ3e+Ox+AkI='; script-src-attr 'none'; style-src 'self' https: 'sha256-pyVPiLlnqL9OWVoJPs/E6VVF5hBecRzM2gBiarnaqAo='; upgrade-insecure-requests;"

describe('ContentSecurityPolicyParser', () => {
  it('toString() should equals input policy string', () => {
    expect(new ContentSecurityPolicyParser(defaultHeader).toString()).toBe(defaultHeader);
  });

  it('toString() should equals empty input policy string', () => {
    expect(new ContentSecurityPolicyParser('').toString()).toBe('');
  });

  it('toString() should be empty when input policy string is undefined', () => {
    expect(new ContentSecurityPolicyParser().toString()).toBe('');
  });

  it('get() should throw TypeError', () => {
    expect(() => { new ContentSecurityPolicyParser(defaultHeader).get() }).toThrow(TypeError);
  });

  it('get(directive) should return expected sources', () => {
    const directive = 'default-src';
    const sources = ["'self'"];
    expect(new ContentSecurityPolicyParser(defaultHeader).get(directive)).toStrictEqual(sources);
  });

  it('get(missing_directive) should return null', () => {
    const directive = 'my-src';
    const sources = null;
    expect(new ContentSecurityPolicyParser(defaultHeader).get(directive)).toBe(sources);
  });

  it('remove() should throw TypeError', () => {
    expect(() => { new ContentSecurityPolicyParser(defaultHeader).remove() }).toThrow(TypeError);
  });

  it('after remove(directive) directive should be missing', () => {
    const policy = new ContentSecurityPolicyParser(defaultHeader);
    const directive = 'default-src';
    const sources = null;
    policy.remove(directive);
    expect(policy.get(directive)).toBe(sources);
  });

  it('after remove(missing_directive) policy should be unchanged', () => {
    const originalPolicy = new ContentSecurityPolicyParser();
    const updatedPolicy = new ContentSecurityPolicyParser();
    const directive = 'my-src';
    updatedPolicy.remove(directive);
    expect(updatedPolicy).toStrictEqual(originalPolicy);
  });

  it('set() should throw TypeError', () => {
    expect(() => { new ContentSecurityPolicyParser(defaultHeader).set() }).toThrow(TypeError);
  });

  it('after set(directive, sources_as_array), get(directive) should return expected sources', () => {
    const policy = new ContentSecurityPolicyParser();
    const directive = 'my-src';
    const sources = ["'self'"];
    policy.set(directive, sources);
    expect(policy.get(directive)).toStrictEqual(sources);
  });

  it('after set(directive, sources_as_array_of_null_or_undefined), get(directive) should return null', () => {
    const policy = new ContentSecurityPolicyParser();
    const directive = 'my-src';
    const sources = [null, undefined];
    policy.set(directive, sources);
    expect(policy.get(directive)).toBeNull();
  });

  it('after set(directive, source_as_string), get(directive) should return expected sources', () => {
    const policy = new ContentSecurityPolicyParser();
    const directive = 'my-src';
    const sources = "'self'";
    policy.set(directive, sources);
    expect(policy.get(directive)).toStrictEqual([sources]);
  });

  it('after set(directive, null), get(directive) should return null', () => {
    const policy = new ContentSecurityPolicyParser();
    const directive = 'my-src';
    const sources = null;
    policy.set(directive, sources);
    expect(policy.get(directive)).toStrictEqual(null);
  });

  it('after add_source(directive, null), get(directive) should return null', () => {
    const policy = new ContentSecurityPolicyParser();
    const directive = 'my-src';
    const sources = null;
    policy.add_source(directive, sources);
    expect(policy.get(directive)).toStrictEqual(null);
  });

  it('after add_source(directive, empty_array), get(directive) should return null', () => {
    const policy = new ContentSecurityPolicyParser();
    const directive = 'my-src';
    const sources = [];
    policy.set(directive, sources);
    expect(policy.get(directive)).toStrictEqual(null);
  });

  it('after add_source(directive, array), get(directive) should return expected sources', () => {
    const policy = new ContentSecurityPolicyParser();
    const directive = 'my-src';
    const sources = ["'self'"];
    policy.set(directive, sources);
    expect(policy.get(directive)).toStrictEqual(sources);
  });

  it('after add_source(directive, source_as_string), get(directive) should return expected sources', () => {
    const policy = new ContentSecurityPolicyParser();
    const directive = 'my-src';
    const sources = "'self'";
    policy.set(directive, sources);
    expect(policy.get(directive)).toStrictEqual([sources]);
  });

  it('remove_source() should throw TypeError', () => {
    expect(() => { new ContentSecurityPolicyParser(defaultHeader).remove_source() }).toThrow(TypeError);
  });

  it('after remove_source(missing_directive, source), policy should be unchanged', () => {
    const expectedPolicy = new ContentSecurityPolicyParser(defaultHeader);
    const policy = new ContentSecurityPolicyParser(defaultHeader);
    const missingDirective = 'other-src';
    const sources = "'self'";
    policy.remove_source(missingDirective, sources);
    expect(policy).toStrictEqual(expectedPolicy);
  });

  it('after remove_source(directive, missing_source_as_string), policy should be unchanged', () => {
    const expectedPolicy = new ContentSecurityPolicyParser(defaultHeader);
    const policy = new ContentSecurityPolicyParser(defaultHeader);
    const missingDirective = 'default-src';
    const sources = "data:";
    policy.remove_source(missingDirective, sources);
    expect(policy).toStrictEqual(expectedPolicy);
  });

  it('after remove_source(directive, source_as_string), removed source should not be in directive', () => {
    const policy = new ContentSecurityPolicyParser(defaultHeader);
    const directive = 'font-src';
    const sources = "data:";
    const expectedSources = ["'self'", 'https:'];
    policy.remove_source(directive, sources);
    expect(policy.get(directive)).toStrictEqual(expectedSources);
  });

  // def test_remove_directive_source_array():
  //     policy = ContentSecurityPolicy("my-src 'self' data:;")
  //     policy.remove_source('my-src', ["'self'"])
  //     assert policy.get('my-src') == ['data:']

  it('after remove_source(directive, sources_as_array), removed sources should not be in directive', () => {
    const policy = new ContentSecurityPolicyParser(defaultHeader);
    const directive = 'font-src';
    const sources = ["data:"];
    const expectedSources = ["'self'", 'https:'];
    policy.remove_source(directive, sources);
    expect(policy.get(directive)).toStrictEqual(expectedSources);
  });

});
