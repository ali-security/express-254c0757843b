'use strict'

var express = require('..');
var request = require('supertest');
var utils = require('./support/utils');

describe('res', function(){
  describe('.links(obj)', function(){
    it('should set Link header field', function (done) {
      var app = express();

      app.use(function (req, res) {
        res.links({
          next: 'http://api.example.com/users?page=2',
          last: 'http://api.example.com/users?page=5'
        });
        res.end();
      });

      request(app)
      .get('/')
      .expect('Link', '<http://api.example.com/users?page=2>; rel="next", <http://api.example.com/users?page=5>; rel="last"')
      .expect(200, done);
    })

    it('should set Link header field for multiple calls', function (done) {
      var app = express();

      app.use(function (req, res) {
        res.links({
          next: 'http://api.example.com/users?page=2',
          last: 'http://api.example.com/users?page=5'
        });

        res.links({
          prev: 'http://api.example.com/users?page=1'
        });

        res.end();
      });

      request(app)
      .get('/')
      .expect('Link', '<http://api.example.com/users?page=2>; rel="next", <http://api.example.com/users?page=5>; rel="last", <http://api.example.com/users?page=1>; rel="prev"')
      .expect(200, done);
    })

    it('should not alter valid URLs and relation types', function (done) {
      var app = express();

      app.use(function (req, res) {
        res.links({
          'prev first': 'http://api.example.com/users?page=1&sort=name,id;v=1',
          'http://example.com/rel/custom': 'http://api.example.com/users/%E2%98%83?q=%22a%22'
        });
        res.end();
      });

      request(app)
      .get('/')
      .expect('Link', '<http://api.example.com/users?page=1&sort=name,id;v=1>; rel="prev first", <http://api.example.com/users/%E2%98%83?q=%22a%22>; rel="http://example.com/rel/custom"')
      .expect(200, done);
    })

    it('should encode the URL to prevent link injection', function (done) {
      var app = express();

      app.use(function (req, res) {
        res.links({
          next: 'http://api.example.com/users?page=2>; rel="preload"; as="script", <http://evil.com/malicious.js'
        });
        res.end();
      });

      request(app)
      .get('/')
      .expect('Link', '<http://api.example.com/users?page=2%3E;%20rel=%22preload%22;%20as=%22script%22,%20%3Chttp://evil.com/malicious.js>; rel="next"')
      .expect(200, done);
    })

    it('should encode control characters in the URL', function (done) {
      var app = express();

      app.use(function (req, res) {
        res.links({
          next: 'http://api.example.com/users?page=2\r\nSet-Cookie: foo=bar'
        });
        res.end();
      });

      request(app)
      .get('/')
      .expect('Link', '<http://api.example.com/users?page=2%0D%0ASet-Cookie:%20foo=bar>; rel="next"')
      .expect(utils.shouldNotHaveHeader('Set-Cookie'))
      .expect(200, done);
    })

    it('should encode quotes in the relation type to prevent link injection', function (done) {
      var app = express();

      app.use(function (req, res) {
        var links = {};
        links['next", <http://evil.com/malicious.js>; rel="preload'] = 'http://api.example.com/users?page=2';
        res.links(links);
        res.end();
      });

      request(app)
      .get('/')
      .expect('Link', '<http://api.example.com/users?page=2>; rel="next%22, %3Chttp://evil.com/malicious.js%3E; rel=%22preload"')
      .expect(200, done);
    })

    it('should encode backslashes in the relation type', function (done) {
      var app = express();

      app.use(function (req, res) {
        var links = {};
        links['next\\'] = 'http://api.example.com/users?page=2';
        links.last = 'http://api.example.com/users?page=5';
        res.links(links);
        res.end();
      });

      request(app)
      .get('/')
      .expect('Link', '<http://api.example.com/users?page=2>; rel="next%5C", <http://api.example.com/users?page=5>; rel="last"')
      .expect(200, done);
    })

    it('should encode control characters in the relation type', function (done) {
      var app = express();

      app.use(function (req, res) {
        var links = {};
        links['next\r\nSet-Cookie: foo=bar'] = 'http://api.example.com/users?page=2';
        res.links(links);
        res.end();
      });

      request(app)
      .get('/')
      .expect('Link', '<http://api.example.com/users?page=2>; rel="next%0D%0ASet-Cookie: foo=bar"')
      .expect(utils.shouldNotHaveHeader('Set-Cookie'))
      .expect(200, done);
    })
  })
})
