<?php

declare(strict_types=1);

use setasign\SetaPDF\Signer\Module\Cumulo\Client;
use setasign\SetaPDF\Signer\Module\Cumulo\Module;

ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

require_once(__DIR__ . '/../vendor/autoload.php');

session_start();

if (!file_exists('settings.php')) {
    echo 'The settings.php file is missing. See settings.php.dist for an example.';
    die();
}

$settings = require 'settings.php';

$fileToSign = __DIR__ . '/assets/Laboratory-Report.pdf';

// to create or update your access token you have to call generate-token.php first
if (!isset($_SESSION['accessToken']['access_token'])) {
    echo 'Missing access token! <a href="generate-token.php">Login here</a>';
    die();
}
// check if the access token is still valid
if (!isset($_SESSION['accessToken']['expires']) || $_SESSION['accessToken']['expires'] < time()) {
    echo 'Access token is expired! <a href="generate-token.php">Renew here</a>';
    die();
}
$accessToken = $_SESSION['accessToken']['access_token'];

$httpClient = new GuzzleHttp\Client([
    'allow_redirects' => true
]);
$requestFactory = new Http\Factory\Guzzle\RequestFactory();
$streamFactory = new Http\Factory\Guzzle\StreamFactory();
$client = new Client($settings['apiUrl'], $accessToken, $httpClient, $requestFactory, $streamFactory);

if (!isset($_POST['certificateId'], $_POST['otp'])) {
    $certificateInfos = $client->listCertificates();
    echo '<pre>' . json_encode($certificateInfos, JSON_PRETTY_PRINT) . '</pre>';

    $id = ($_POST['certificateId'] ?? $certificateInfos[1]['id']);
    echo '<table>'
        . '<tr><td>'
        . '<iframe src="assets/Laboratory-Report.pdf" style="width: 500px; height: 500px;"></iframe>'
        . '</td><td style="vertical-align: top;">'
        . '<form method="post">'
        . '<label for="certificateId">Certificate-ID: </label>'
        . '<input type="text" id="certificateId" name="certificateId" value="' . $id . '" style="width: 300px;"/><br/><br/>'
        . '<label for="algorithm">Signing Algorithm: </label>'
        . '<select name="algorithm" id="algorithm">'
        . '<option value="RS256">RS256</option>'
        . '<option value="RS384">RS384</option>'
        . '<option value="RS512">RS512</option>'
        . '<option value="ES256">ES256</option>'
        . '<option value="ES384">ES384</option>'
        . '<option value="ES512">ES512</option>'
        . '</select><br/><br/>'
        . '<label for="otp">OTP: </label>'
        . '<input type="text" id="otp" name="otp" value=""/><br/><br/>'
        . '<input type="submit" value="Sign"/>'
        . '</form>'
        . '</td></tr>'
        . '</table>';
    die();
}

try {
    $module = new Module($client);
    $module->setCertificateId($_POST['certificateId']);
    $module->setOtp($_POST['otp']);
    $module->setSigningAlgorithm($_POST['algorithm']);

    // create a writer instance
    $writer = new SetaPDF_Core_Writer_String();
    $tmpWriter = new SetaPDF_Core_Writer_TempFile();
    // create the document instance
    $document = SetaPDF_Core_Document::loadByFilename($fileToSign, $tmpWriter);

    // create the signer instance
    $signer = new SetaPDF_Signer($document);
    $signer->setAllowSignatureContentLengthChange(false);
    $signer->setSignatureContentLength(26000);

    $chainCertificates = SetaPDF_Signer_Pem::extract($client->getCertificateSigningChain($_POST['certificateId']));
//    var_dump('<pre>');
//    /**
//     * @var SetaPDF_Signer_X509_Certificate $chainCertificate
//     */
//    foreach ($chainCertificates as $chainCertificate) {
//        var_dump($chainCertificate->getSubjectName(), $chainCertificate->getIssuerName(), '<hr/>');
//    }
//    die();
    $module->setExtraCertificates($chainCertificates);

    $signer->setReason('Testing Cumulo!');

    $field = $signer->getSignatureField();
    $fieldName = $field->getQualifiedName();
    $signer->setSignatureFieldName($fieldName);

    $signer->sign($module);


    $document = \SetaPDF_Core_Document::loadByFilename($tmpWriter->getPath(), $writer);

    // Create a collection of trusted certificats:
    $trustedCertificates = new SetaPDF_Signer_X509_Collection($chainCertificates);

    // Create a collector instance
    $collector = new SetaPDF_Signer_ValidationRelatedInfo_Collector($trustedCertificates);

    try {
        // Collect revocation information for this field
        $vriData = $collector->getByFieldName($document, $fieldName);
    } catch (Throwable $e) {
        // Debug process for resolving verification related information
        echo '<h1>Error on collecting the ValidationRelatedInfo</h1><pre>';
        foreach ($collector->getLogger()->getLogs() as $log) {
            echo str_repeat(' ', $log->getDepth() * 4) . $log . "\n";
        }
        die();
    }

    $dss = new SetaPDF_Signer_DocumentSecurityStore($document);
    $dss->addValidationRelatedInfoByFieldName(
        $fieldName,
        $vriData->getCrls(),
        $vriData->getOcspResponses(),
        $vriData->getCertificates()
    );

    $document->save()->finish();

    echo '<a href="data:application/pdf;base64,' . base64_encode($writer->getBuffer()) . '" ' .
        'download="result.pdf">download</a> | <a href="?">restart</a><br />';

} catch (Throwable $e) {
    echo 'An error occurred: <pre>' . $e . '</pre>';

    echo '<hr/><a href="?">restart</a>';
}