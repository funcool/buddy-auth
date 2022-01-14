# Changelog

## Version 3.0.323

Date: 2022-01-14

- Update dependencies.
- Minimum JDK == 8.


## Version 3.0.1

Date: 2021-05-02

- Update buddy-sign to 3.4.1


## Version 3.0.0

Date: 2021-05-02

- Dependencies update
- Documentation changes.


## Version 2.2.0

Date: 2018-06-28

- Add support for async ring handlers
- Update deps.


## Version 2.1.0

Date: 2017-08-29

- Update buddy-sign to 2.2.0


## Version 2.0.0

Date: 2017-08-10

- Allow keywords for HTTP headers as well as strings
- Update to use Clojure 1.9.0-alpha17
- Update buddy-sign to 2.0.0 (implicit breaking change no longer handling `iat` validation)
- Update cuerdas to 2.0.2

## Version 1.4.1

Date: 2017-01-29

- Fix some backward incompatibilities introduced in previous commit.


## Version 1.4.0

Date: 2017-01-24

- Add `authfn` parameter to the rest of backends (thanks to @rymndhng)
- Respect the value of `:identity` on request when no auth backend has
  authenticated the request (usefull for tests).

## Version 1.3.0

Date: 2016-11-15

- Update buddy-sign to 1.3.0
- Update cuerdas to 2.0.1


## Version 1.2.0

Date: 2016-09-01

- Update buddy-sign to 1.2.0
- Update cuerdas to 1.0.1


## Version 1.1.0

Date: 2016-06-11

- Update buddy-sign to 1.1.0


## Version 1.0.0

Date: 2016-05-21

**Important**: This is an major release beacause it includes breaking api changes.

- Update buddy-sign dependency to 1.0.0 that includes breaking changes. For
  more information, refer to buddy-sign release notes:
  https://github.com/funcool/buddy-sign/blob/master/CHANGES.adoc#version-100



## Version 0.13.0

Date: 2016-04-23

- Update buddy-sign dependency to 0.13.0.


## Version 0.12.0

Date: 2016-04-09

- Update buddy-sign dependency to 0.12.0
- Improve backends api (fully backward compatible).


## Version 0.11.0

Date: 2016-03-27

- Update buddy-sign dependency to 0.11.0


## Version 0.10.0

Date: 2016-03-26

- Update buddy-sign dependency to 0.10.0


## Version 0.9.0

Date: 2016-01-06

- Update buddy-sign dependency to 0.9.0.


## Version 0.8.2

Date: 2015-12-08

- Fixed wrong handling passwords with colons (thanks @mitch-kile).


## Version 0.8.1

Date: 2015-11-17

- Update buddy-sign to 0.8.1


## Version 0.8.0

Date: 2015-11-15

- Update buddy-sign to 0.8.0
- Implicit update to buddy-core 0.8.1


## Version 0.7.1

Date: 2015-10-03

- Fix wrong call to `throw` on `wrap-authorization` middleware.
- Update buddy-sign version to 0.7.1


## Version 0.7.0

Date: 2015-09-19

- Response return value is now not supported in `parse` step of the authentication.
- The `on-error` handler now receives plain exception info instance instead
  the error data. This maybe a little breaking change caused by exception handling
  changes on buddy-core and buddy-sign.


## Version 0.6.2

Date: 2015-08-26

- The regext access rule matcher now only uses the request `:uri` property.


## Version 0.6.1

Date: 2015-08-02

- Set default clojure version to 1.7.0
- Update buddy-sign version to 0.6.1
- Update cuerdas version to 0.6.0


## Version 0.6.0

Date: 2015-06-28

- Update to buddy-sign 0.6.0
- Update to buddy-core 0.6.0
- Update cuerdas to 0.5.0


## Version 0.5.3

Date: 2015-05-16

- Remove ring dependency.
- Implement some http related functios as protocols for easy
  extensibility by third party. Making it more compatible with
  `funcool/catacumba` as example.

## Version 0.5.2

Date: 2015-05-09

- Update clout version to 2.1.2
- Update buddy-sign version to 0.5.1 (that fixes unexpected exceptions on parsing wrong tokens)


## Version 0.5.1

Date: 2015-04-16

- Add support for access to uri matching tokens when clout url matching
  system is used in access rules.


## Version 0.5.0

Date: 2015-04-03

- Update buddy-sign to 0.5.0
- Add JWE (Json Web Token) auth backend.
- Improved exception based ahorization functions.
- Add `on-error` parameter to JWS backend.
- Add support for multiple backends. (thanks to @r0man)
- Add support for match for http method for acces rules (thanks to @r0man)
- Fix wrong behavior :or logic operator on access rules dsl (thanks to @r0man)
- Removed any java source, now is 100% clojure.


## Version 0.4.2

Date: 2015-03-29

- Update buddy-sign to 0.4.2


## Version 0.4.1

Date: 2015-03-14

- Fix bug in uri handling in accessrules.
- Remove unnecesary headers normalization.
- Upgrade buddy-sign to 0.4.1
- Upgrade buddy-core to 0.4.2
- Upgrade cuerdas to 0.3.1


## Version 0.4.0

Date: 2014-02-22

- Removed signed token backend.
- Add jws backend, as replacement for signed token backend.
- Update buddy-core version to 0.4.0
- Update buddy-sign vetsion to 0.4.0
- Update slingshot to 0.12.2


## Version 0.3.0

Date: 2015-01-24

- First version splitted from monolitic buddy package.
- Refactored auth access rules module with features from
  https://github.com/yogthos/ring-access-rules
- Fix bugs on auth backends related to headers parsing.
