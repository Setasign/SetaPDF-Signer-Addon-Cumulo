# SetaPDF-Signer-Addon-Cumulo
This package offers a module for the [SetaPDF-Signer](https://www.setasign.com/signer) component that allow you to use 
the [Cumulo API](https://cumulo.jupiter.isolvtech.com:7443/docs/api.html) to digital sign PDF documents in pure PHP.


## Requirements

To use this package you need credentials for the Cumulo API.

This package is developed and tested on PHP >= 7.2. Requirements of the [SetaPDF-Signer](https://www.setasign.com/signer)
component can be found [here](https://manuals.setasign.com/setapdf-signer-manual/getting-started/#index-1).

We're using [PSR-17 (HTTP Factories)](https://www.php-fig.org/psr/psr-17/) and [PSR-18 (HTTP Client)](https://www.php-fig.org/psr/psr-18/)
for the requests. So you'll need an implementation of these. We recommend using Guzzle.

```
    "require" : {
        "guzzlehttp/guzzle": "^7.0",
        "http-interop/http-factory-guzzle": "^1.0"
    }
```

Additionally to request an access token you'll need an oauth2 implementation such
as [league/oauth2-client](https://github.com/thephpleague/oauth2-client).

Sample code for this can be found in "[examples/generate-token.php](examples/generate-token.php)".

Please note: because of oauth2 your domain MUST be available through HTTPS.

## Installation
Add following to your composer.json:

```json
{
    "require": {
        "setasign/setapdf-signer-addon-cumulo": "^1.0"
    },
    "repositories": [
        {
            "type": "composer",
            "url": "https://www.setasign.com/downloads/"
        }
    ]
}
```

and execute `composer update`. You need to define the `repository` to evaluate the dependency to the
[SetaPDF-Signer](https://www.setasign.com/signer) component
(see [here](https://getcomposer.org/doc/faqs/why-can%27t-composer-load-repositories-recursively.md) for more details).

### Trial version
By default, this packages depends on a licensed version of the [SetaPDF-Signer](https://www.setasign.com/signer)
component. If you want to use it with a trial version please use following in your composer.json:

```json
{
    "require": {
        "setasign/setapdf-signer-addon-cumulo": "dev-trial"
    },
    "repositories": [
        {
            "type": "composer",
            "url": "https://www.setasign.com/downloads/"
        }
    ]
}
```

## License

This package is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).
