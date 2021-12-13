# Content Security Policy Parser

## Installation

```bash
npm install --save-dev @dgarrido/yacspp
```

## Usage

```javascript
#!/usr/bin/env node
const { ContentSecurityPolicyParser } = require('@dgarrido/yacspp');

const header = "default-src 'self'; base-uri 'self'; block-all-mixed-content; font-src 'self' https: data:; frame-ancestors 'self'; img-src 'self' data: www.example.com; object-src 'none'; script-src 'self' 'sha256-2yQBTLGLI1sDcBILfj/o6b5ufMv6CEwPYOk3RZI/WjE=' 'sha256-GeDavzSZ8O71Jggf/pQkKbt52dfZkrdNMQ3e+Ox+AkI='; script-src-attr 'none'; style-src 'self' https: 'sha256-pyVPiLlnqL9OWVoJPs/E6VVF5hBecRzM2gBiarnaqAo='; upgrade-insecure-requests;";

const originalPolicy = new ContentSecurityPolicyParser(header);
const updatedPolicy = new ContentSecurityPolicyParser(header);

const filteredOutDirectives = ['block-all-mixed-content']
newDirectives = {
  'sandbox': null,
  'my-src': ["'self'", 'http:', 'https:']
}
const augmentedDirectives = {
  'default-src': ['http:', 'https:']
}
const diminishedDirectives = {
  'img-src': ['www.example.com']
}

// Filter out directives
for ([directive, sources] of Object.entries(originalPolicy.directives)) {
  if (filteredOutDirectives.includes(directive)) {
    updatedPolicy.remove(directive)
  }
}

// Add new directives
for ([directive, sources] of Object.entries(newDirectives)) {
  updatedPolicy.add_source(directive, sources)
}

// Add sources to directives
for ([directive, sources] of Object.entries(augmentedDirectives)) {
  updatedPolicy.add_source(directive, sources)
}

// Remove sources from directives
for ([directive, sources] of Object.entries(diminishedDirectives)) {
  updatedPolicy.remove_source(directive, sources)
}

console.log(originalPolicy.directives)
console.log(updatedPolicy.directives)
console.log(originalPolicy.toString())
console.log(updatedPolicy.toString())
```
