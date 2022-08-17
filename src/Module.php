<?php

declare(strict_types=1);

/**
 * @copyright Copyright (c) 2022 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

namespace setasign\SetaPDF\Signer\Module\Cumulo;

use InvalidArgumentException;
use SetaPDF_Core_Reader_FilePath;
use SetaPDF_Signer_Asn1_Element as Asn1Element;
use SetaPDF_Signer_Digest as Digest;
use SetaPDF_Signer_Signature_DictionaryInterface as DictionaryInterface;
use SetaPDF_Signer_Signature_DocumentInterface as DocumentInterface;
use SetaPDF_Signer_Signature_Module_ModuleInterface as ModuleInterface;
use SetaPDF_Signer_Signature_Module_PadesProxyTrait as PadesProxyTrait;

class Module implements ModuleInterface, DictionaryInterface, DocumentInterface
{
    use PadesProxyTrait;

    /**
     * @var Client
     */
    protected $client;

    /**
     * @var string
     */
    protected $certificateId;

    /**
     * @var null|string
     */
    protected $otp;

    /**
     * @var string
     */
    protected $signingAlgorithm = 'RS512';

    public function __construct(
        Client $client
    ) {
        $this->client = $client;
    }

    public function setCertificateId(string $certificateId)
    {
        $this->certificateId = $certificateId;
    }

    public function setSigningAlgorithm(string $algorithm)
    {
        switch ($algorithm) {
            case 'RS256':
            case 'ES256':
                $hashingAlgorithm = Digest::SHA_256;
                break;
            case 'RS384':
            case 'ES384':
                $hashingAlgorithm = Digest::SHA_384;
                break;
            case 'RS512':
            case 'ES512':
                $hashingAlgorithm = Digest::SHA_512;
                break;
            default:
                throw new InvalidArgumentException('Invalid signing algorithm!');
        }
        $this->signingAlgorithm = $algorithm;
        $this->_getPadesModule()->setDigest($hashingAlgorithm);
    }

    public function setOtp(string $otp): void
    {
        $this->otp = $otp;
    }

    public function getCertificate()
    {
        $padesModule = $this->_getPadesModule();
        if ($padesModule->getCertificate() === null) {
            $certificate = $this->client->getCertificatePEM($this->certificateId);
            $padesModule->setCertificate($certificate);
        }
        return $padesModule->getCertificate();
    }

    public function createSignature(SetaPDF_Core_Reader_FilePath $tmpPath)
    {
        if ($this->otp === null) {
            throw new \BadMethodCallException('Missing otp!');
        }

        // ensure certificate
        $certificate = $this->getCertificate();
        if ($certificate === null) {
            throw new \BadMethodCallException('Missing certificate!');
        }

        $padesModule = $this->_getPadesModule();
        // get the hash data from the module
        $padesDigest = $padesModule->getDigest();

        $hashData = hash($padesDigest, $padesModule->getDataToSign($tmpPath), true);
        $signatureValue = $this->client->signWithOtp(
            $this->certificateId,
            $this->signingAlgorithm,
            $hashData,
            $this->otp
        );

        if (\in_array($this->signingAlgorithm, ['ES256', 'ES384', 'ES512'], true)) {
            // THIS NEEDS TO BE USED TO FIX EC SIGNATURES
            $len = strlen($signatureValue);

            $s = substr($signatureValue, 0, $len / 2);
            if (ord($s[0]) & 0x80) { // ensure positive integers
                $s = "\0" . $s;
            }
            $r = substr($signatureValue, $len / 2);
            if (ord($r[0]) & 0x80) { // ensure positive integers
                $r = "\0" . $r;
            }

            $signatureValue = new Asn1Element(
                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                '',
                [
                    new Asn1Element(Asn1Element::INTEGER, $s),
                    new Asn1Element(Asn1Element::INTEGER, $r),
                ]
            );
        }

        // pass it to the module
        $padesModule->setSignatureValue($signatureValue);

        return (string) $padesModule->getCms();
    }
}
