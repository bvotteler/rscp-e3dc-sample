# rscp-e3dc-sample [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
A simplistic sample project showing how the [rscp-e3dc library](https://github.com/bvotteler/rscp-e3dc) could be used
to authenticate with an E3DC server, and send a request to fetch database history data using the proprietary RSCP protocol
from [E3/DC GmbH](https://www.e3dc.com/). 

It also includes a helper class to encrypt and decrypt frames sent to and from an E3DC server. 
See [BouncyAES256Helper.java](./src/main/java/io/github/bvotteler/rscp/sample/Utility/BouncyAES256Helper.java) and its usage for more details.

This sample application is available under the [MIT license](./LICENSE).

## Requirements
* JDK 1.8+
* Maven 3.6

## Build
Build the library with:

`mvn clean compile`

## Test
Run the tests with:

`mvn test`

## Package a jar
Pack the jar with:

`mvn package`