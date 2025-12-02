import _ from 'underscore';
import url from 'url';
import http from 'http';
import https from 'https';
import { parseString } from 'xml2js';
import * as processors from 'xml2js/lib/processors.js';
import passport from 'passport';
import { v4 as uuidv4 } from 'uuid';
import util from 'util';

class Strategy extends passport.Strategy {
  constructor(options, verify) {
    if (typeof options === 'function') {
      verify = options;
      options = {};
    }
    if (!verify) {
      throw new Error('cas authentication strategy requires a verify function');
    }
    super();

    this.version = options.version || "CAS1.0";
    this.ssoBase = options.ssoBaseURL;
    this.serverBaseURL = options.serverBaseURL;
    this.validateURL = options.validateURL;
    this.serviceURL = options.serviceURL;
    this.useSaml = options.useSaml || false;
    this.parsed = url.parse(this.ssoBase);
    this.client = this.parsed.protocol === 'http:' ? http : https;

    this.name = 'cas';
    this._verify = verify;
    this._passReqToCallback = options.passReqToCallback;

    const xmlParseOpts = {
      trim: true,
      normalize: true,
      explicitArray: false,
      tagNameProcessors: [processors.normalize, processors.stripPrefix]
    };

    const self = this;
    switch (this.version) {
      case "CAS1.0":
        this._validateUri = "/validate";
        this._validate = function (req, body, verified) {
          const lines = body.split('\n');
          if (lines.length >= 1) {
            if (lines[0] === 'no') {
              return verified(new Error('Authentication failed'));
            } else if (lines[0] === 'yes' && lines.length >= 2) {
              if (self._passReqToCallback) {
                self._verify(req, lines[1], verified);
              } else {
                self._verify(lines[1], verified);
              }
              return;
            }
          }
          return verified(new Error('The response from the server was bad'));
        };
        break;
      case "CAS3.0":
        if (this.useSaml) {
          this._validateUri = "/samlValidate";
          this._validate = function (req, body, verified) {
            parseString(body, xmlParseOpts, function (err, result) {
              if (err) {
                return verified(new Error('The response from the server was bad'));
              }
              try {
                const response = result.envelope.body.response;
                const success = response.status.statuscode['$'].Value.match(/Success$/);
                if (success) {
                  const attributes = {};

                  _.each(response.assertion.attributestatement.attribute, function (attribute) {
                    attributes[attribute['$'].AttributeName.toLowerCase()] = attribute.attributevalue;
                  });
                  const profile = {
                    user: response.assertion.authenticationstatement.subject.nameidentifier,
                    attributes: attributes
                  };
                  if (self._passReqToCallback) {
                    self._verify(req, profile, verified);
                  } else {
                    self._verify(profile, verified);
                  }
                  return;
                }
                return verified(new Error('Authentication failed'));
              } catch (e) {
                return verified(new Error('Authentication failed'));
              }
            });
          };
        } else {
          this._validateUri = "/p3/serviceValidate";
          this._validate = function (req, body, verified) {
            parseString(body, xmlParseOpts, function (err, result) {
              if (err) {
                return verified(new Error('The response from the server was bad'));
              }
              try {
                if (result.serviceresponse.authenticationfailure) {
                  return verified(new Error('Authentication failed ' + result.serviceresponse.authenticationfailure.$.code));
                }
                const success = result.serviceresponse.authenticationsuccess;
                if (success) {
                  if (self._passReqToCallback) {
                    self._verify(req, success, verified);
                  } else {
                    self._verify(success, verified);
                  }
                  return;
                }
                return verified(new Error('Authentication failed'));
              } catch (e) {
                return verified(new Error('Authentication failed'));
              }
            });
          };
        }
        break;
      default:
        throw new Error('unsupported version ' + this.version);
    }
  }

  /**
   * Generates the service URL for the CAS authentication process.
   *
   * @param {Object} req - The HTTP request object.
   * @returns {string} - The formatted service URL without the ticket parameter.
   */
  service(req) {
    const serviceURL = this.serviceURL || req.originalUrl;
    const resolvedURL = url.resolve(this.serverBaseURL, serviceURL);
    const parsedURL = url.parse(resolvedURL, true);
    delete parsedURL.query.ticket;
    if (parsedURL.search !== undefined) {
      delete parsedURL.search;
    }

    return url.format(parsedURL);
  }

  authenticate(req, options = {}) {
    const relayState = req.query.RelayState;
    if (relayState) {
      req.logout();
      return this.redirect(`${this.ssoBase}/logout?_eventId=next&RelayState=${relayState}`);
    }

    const service = this.service(req);
    const ticket = url.parse(req.url, true).query.ticket;

    if (!ticket) {
      const redirectURL = url.parse(`${this.ssoBase}/login`, true);
      redirectURL.query.service = service;

      for (const property in options.loginParams) {
        const loginParam = options.loginParams[property];
        if (loginParam) {
          redirectURL.query[property] = loginParam;
        }
      }
      return this.redirect(url.format(redirectURL));
    }

    const self = this;
    const verified = function (err, user, info) {
      if (err) {
        return self.error(err);
      }

      if (!user) {
        return self.fail(info);
      }

      self.success(user, info);
    };

    const _validateUri = this.validateURL || this._validateUri;

    const _handleResponse = function (response) {
      response.setEncoding('utf8');
      let body = '';
      response.on('data', chunk => body += chunk);
      response.on('end', () => self._validate(req, body, verified));
    };

    if (this.useSaml) {
      const requestId = uuidv4();
      const issueInstant = new Date().toISOString();
      const soapEnvelope = util.format(
        '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1" RequestID="%s" IssueInstant="%s"><samlp:AssertionArtifact>%s</samlp:AssertionArtifact></samlp:Request></SOAP-ENV:Body></SOAP-ENV:Envelope>',
        requestId, issueInstant, ticket
      );

      const request = this.client.request({
        host: this.parsed.hostname,
        port: this.parsed.port,
        method: 'POST',
        path: url.format({
          pathname: this.parsed.pathname + _validateUri,
          query: { TARGET: service }
        })
      }, _handleResponse);

      request.on('error', e => self.fail(new Error(e.message || 'Unknown error')));
      request.write(soapEnvelope);
      request.end();
    } else {
      const get = this.client.get({
        host: this.parsed.hostname,
        port: this.parsed.port,
        path: url.format({
          pathname: this.parsed.pathname + _validateUri,
          query: { ticket, service }
        })
      }, _handleResponse);

      get.on('error', e => self.fail(new Error(e.message || 'Unknown error')));
    }
  }
}

export { Strategy };
