<?php

declare(strict_types=1);

/**
 * @copyright Copyright (c) 2022 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

namespace setasign\SetaPDF\Signer\Module\Cumulo;

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

class Client
{
    /**
     * @var ClientInterface PSR-18 HTTP Client implementation.
     */
    protected $httpClient;

    /**
     * @var RequestFactoryInterface PSR-17 HTTP Factory implementation.
     */
    protected $requestFactory;

    /**
     * @var StreamFactoryInterface PSR-17 HTTP Factory implementation.
     */
    protected $streamFactory;

    /**
     * @var string
     */
    protected $apiUri;

    /**
     * @var string
     */
    protected $accessToken;

    /**
     * Client constructor.
     *
     * @param non-empty-string $apiUri
     * @param non-empty-string $accessToken
     * @param ClientInterface $httpClient PSR-18 HTTP Client implementation.
     * @param RequestFactoryInterface $requestFactory PSR-17 HTTP Factory implementation.
     * @param StreamFactoryInterface $streamFactory PSR-17 HTTP Factory implementation.
     */
    public function __construct(
        string $apiUri,
        string $accessToken,
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        StreamFactoryInterface $streamFactory
    ) {
        $this->apiUri = \rtrim($apiUri, '/');
        $this->accessToken = $accessToken;
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->streamFactory = $streamFactory;
    }

    /**
     * Helper method to handle errors in json_decode
     *
     * @param string $json
     * @param bool $assoc
     * @param int $depth
     * @param int $options
     * @return mixed
     * @throws Exception
     */
    protected function json_decode(string $json, bool $assoc = true, int $depth = 512, int $options = 0)
    {
        // Clear json_last_error()
        \json_encode(null);

        $data = @\json_decode($json, $assoc, $depth, $options);

        if (\json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception(\sprintf(
                'Unable to decode JSON: %s',
                \json_last_error_msg()
            ));
        }

        return $data;
    }

    /**
     * Encode data to Base64URL
     *
     * @param string $data
     * @return string
     */
    protected function base64url_encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Decode data from Base64URL
     *
     * @param string $data
     * @return string
     */
    protected function base64url_decode(string $data): string
    {
        return base64_decode(strtr($data, '-_', '+/'), true);
    }

    /**
     * @return array
     * @throws ClientExceptionInterface
     * @throws Exception
     */
    public function listCertificates(): array
    {
        $request = (
            $this->requestFactory->createRequest('GET', $this->apiUri  . '/certificates')
            ->withHeader('Authorization', 'Bearer ' . $this->accessToken)
        );

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on /certificates: ' . $response->getBody());
        }

        return $this->json_decode((string) $response->getBody());
    }

    /**
     * @param non-empty-string $id
     * @return array{
     *   id: string,
     *   name: string,
     *   created_at: string,
     *   not_before: string,
     *   not_after: string,
     *   subject: string,
     *   issuer: string,
     *   serial_number: string,
     *   key: string
     * }
     * @throws ClientExceptionInterface
     * @throws Exception
     */
    public function getCertificateDetails(string $id): array
    {
        $request = (
            $this->requestFactory->createRequest('GET', $this->apiUri  . '/certificates/' . $id)
            ->withHeader('Authorization', 'Bearer ' . $this->accessToken)
        );

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on /certificates/{id}: ' . $response->getBody());
        }

        return $this->json_decode((string) $response->getBody());
    }

    /**
     * @param non-empty-string $id
     * @return string
     * @throws ClientExceptionInterface
     * @throws Exception
     */
    public function getCertificatePEM(string $id): string
    {
        $request = (
            $this->requestFactory->createRequest('GET', $this->apiUri  . '/certificates/' . $id . '/pem')
            ->withHeader('Authorization', 'Bearer ' . $this->accessToken)
        );

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on /certificates/{id}/pem: ' . $response->getBody());
        }

        return (string) $response->getBody();
    }

    /**
     * @param non-empty-string $id
     * @return string
     * @throws ClientExceptionInterface
     * @throws Exception
     */
    public function getCertificateSigningChain(string $id): string
    {
        $request = (
            $this->requestFactory->createRequest('GET', $this->apiUri  . '/certificates/' . $id . '/chain?return=all')
            ->withHeader('Authorization', 'Bearer ' . $this->accessToken)
        );

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on /certificates/{id}/chain: ' . $response->getBody());
        }

        return (string) $response->getBody();
    }

    /**
     * @param string $id
     * @param string $otp
     * @param int $numSignatures
     * @return array{sad: string, ttl: int}
     * @throws ClientExceptionInterface
     * @throws Exception
     */
    public function authorize(string $id, string $otp, int $numSignatures = 1): array
    {
        $inputData = \json_encode([
            'otp' => $otp,
            'num_signatures' => $numSignatures
        ]);

        $request = (
            $this->requestFactory->createRequest('POST', $this->apiUri  . '/certificates/' . $id . '/authorize')
            ->withHeader('Authorization', 'Bearer ' . $this->accessToken)
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->streamFactory->createStream($inputData))
        );

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on /certificates/{id}/authorize: ' . $response->getBody());
        }

        return $this->json_decode((string) $response->getBody());
    }

    /**
     * @param string $id
     * @param string $signingAlgorithm
     * @param string $dataToBeSigned The data to be signed. Binary hash of the document.
     * @param string $otp
     * @return string The signature.
     * @throws ClientExceptionInterface
     * @throws Exception
     */
    public function signWithOtp(string $id, string $signingAlgorithm, string $dataToBeSigned, string $otp): string
    {
        $inputData = \json_encode([
            'signing_algorithm' => $signingAlgorithm,
            'tbs' => $this->base64url_encode($dataToBeSigned),
            'otp' => $otp
        ]);

        $request = (
        $this->requestFactory->createRequest('POST', $this->apiUri  . '/certificates/' . $id . '/sign')
            ->withHeader('Authorization', 'Bearer ' . $this->accessToken)
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->streamFactory->createStream($inputData))
        );

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on /certificates/{id}/sign: ' . $response->getBody());
        }

        $responseData = $this->json_decode((string) $response->getBody());
        return $this->base64url_decode($responseData['signature']);
    }

    /**
     * @param string $id
     * @param string $signingAlgorithm
     * @param string $dataToBeSigned The data to be signed. Binary hash of the document.
     * @param string $sad
     * @return string The signature.
     * @throws ClientExceptionInterface
     * @throws Exception
     */
    public function signWithSad(string $id, string $signingAlgorithm, string $dataToBeSigned, string $sad): string
    {
        $inputData = \json_encode([
            'signing_algorithm' => $signingAlgorithm,
            'tbs' => $this->base64url_encode($dataToBeSigned),
            'sad' => $sad
        ]);

        $request = (
        $this->requestFactory->createRequest('POST', $this->apiUri  . '/certificates/' . $id . '/sign')
            ->withHeader('Authorization', 'Bearer ' . $this->accessToken)
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->streamFactory->createStream($inputData))
        );

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on /certificates/{id}/sign: ' . $response->getBody());
        }

        $responseData = $this->json_decode((string) $response->getBody());
        return $this->base64url_decode($responseData['signature']);
    }
}
