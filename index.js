const filterValues = (array) => {
  if (!(array instanceof Array))
    return array;
  return array.filter(function (value) {
    return typeof (value) === 'string' && value.length > 0;
  });
}

class ContentSecurityPolicyParser {
  constructor(policyString = null) {
    this.directives_regexp = "([a-z-]*)(?: *(.*?)); *";
    this.sources_regex = "('[^']+?'|[^ ]+)";
    this.directives = {};
    if (policyString) {
      this.parseCspString(policyString);
    }
  }

  parseCspString(policyString) {
    const directives = policyString.matchAll(this.directives_regexp, 'g')
    for (const directive of directives) {
      const directiveName = directive[1];
      const sourcesString = directive[2];
      if (sourcesString) {
        this.directives[directiveName] = [];
        const sources = sourcesString.matchAll(this.sources_regex, 'g');
        for (let source of sources) {
          this.directives[directiveName].push(source[1]);
        }
      }
      else {
        this.directives[directiveName] = null;
      }
    }
  }

  toString() {
    let directives = [];
    for (const [directive, sources] of Object.entries(this.directives)) {
      if (sources !== null) {
        directives.push(`${directive} ${sources.join(' ')};`);
      } else {
        directives.push(`${directive};`);
      }
    }

    return directives.join(' ');
  }

  get(directive) {
    if (!directive) {
      throw TypeError(`directive: ${directive}`);
    }
    if (!this.directives.hasOwnProperty(directive)) {
      return null;
    }
    if (!this.directives[directive] instanceof Array)
      throw TypeError('directives');
    return this.directives[directive];
  }

  remove(directive) {
    if (!directive) {
      throw TypeError(`directive: ${directive}`);
    }
    if (!this.directives.hasOwnProperty(directive)) {
      return;
    }
    delete this.directives[directive];
  }

  set(directive, sources = null) {
    if (!directive) {
      throw TypeError(`directive: ${directive}`);
    }
    if (sources === null) {
      this.directives[directive] = null;
      return;
    }
    if (!(sources instanceof Array)) {
      this.directives[directive] = [sources];
      return;
    }
    sources = filterValues(sources);
    if (sources.length === 0) {
      this.directives[directive] = null;
      return;
    }
    this.directives[directive] = sources;
  }

  add_source(directive, sources) {
    if (!directive) {
      throw TypeError(`directive: ${directive}`);
    }
    if (!this.directives.hasOwnProperty(directive)) {
      this.directives[directive] = null;
    }
    sources = filterValues(sources);
    if (!sources || (sources instanceof Array && sources.length === 0)) {
      return;
    }
    if (this.directives[directive] === null) {
      this.directives[directive] = [];
    }
    if (sources instanceof Array) {
      this.directives[directive].push(...sources);
    } else {
      this.directives[directive].push(sources);
    }
  }

  remove_source(directive, sources) {
    if (!directive) {
      throw TypeError(`directive: ${directive}`);
    }
    if (!this.directives.hasOwnProperty(directive)) {
      return;
    }
    const directiveSources = this.directives[directive];
    if (sources instanceof Array) {
      for (const source of sources) {
        const index = directiveSources.indexOf(source);
        if (index > -1) {
          directiveSources.splice(index, 1);
        }
      }
    } else {
      const index = directiveSources.indexOf(sources);
      if (index > -1) {
        directiveSources.splice(index, 1);
      }
    }
  }
}

module.exports = {
  ContentSecurityPolicyParser,
};
