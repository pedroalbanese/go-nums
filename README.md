# NUMS
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/go-nums/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/go-nums?status.png)](http://godoc.org/github.com/pedroalbanese/go-nums)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/go-nums)](https://goreportcard.com/report/github.com/pedroalbanese/go-nums)

### Microsoft Nothing Up My Sleeve Elliptic curves
[NUMS](http://www.watersprings.org/pub/id/draft-black-numscurves-01.html) (Nothing Up My Sleeve) curves, which are supported in the MSRElliptic Curve Cryptography Library (a.k.a. MSR ECCLib).

These curves are elliptic curves over a prime field, just like the NIST or Brainpool curves. However, the domain-parameters are choosen using a VERY TIGHT DESIGN SPACE to ensure, that the introduction of a backdoor is infeasable. For a desired size of s bits the prime p is choosen as p = 2^s - c with the smallest c where c>0 and p mod 4 = 3 and p being prime.
