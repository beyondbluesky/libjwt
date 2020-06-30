<?php

/* 
 *  The Creative Commons BY-NC-SA 4.0 License
 *  Attribution-NonCommercial-ShareAlike 4.0 International
 * 
 *  Josep Llauradó Selvas
 *  pep@beyondbluesky.com
 * 
 *  For the full copyright and license information, please view the LICENSE
 *  file that was distributed with this source code.
 */

namespace BeyondBlueSky\LibJWT\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;

use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\Config\FileLocator;

use BeyondBlueSky\LibJWT\Entity\JWToken;
use BeyondBlueSky\LibJWT\Entity\JWTHeader;
use BeyondBlueSky\LibJWT\Entity\JWTPayload;

class JWTServiceExtension extends Extension {
    
    public function load(array $configs, ContainerBuilder $container)
    {
        $loader = new YamlFileLoader(
            $container,
            new FileLocator(__DIR__.'/../Resources/config')
            );
        $loader->load('services.yml');
        
        //$configuration = new Configuration();
        //$config = $this->processConfiguration($configuration, $configs);

        $definition = $container->getDefinition(JWTServiceExtension::class);
        
    }
    
    public function decode(string $token): JWToken {
        $jwtoken= new JWToken();
        
        $jwtoken->restore($token);
        
        return $jwtoken;
    }
    
    public function inClaims(JWToken $jwToken, string $target, string $method ){
        $isAllowed= false;
        
        $action = $this->getActionFromMethod( $method );
        $claims = $jwToken->getClaims();
        $claims = $this->getFullClaims($jwToken->getIss(), $claims);
        
        if( isset( $claims[$target] ) ){
            // The resource is found on claims
            $allowedAccessString = $claims[ $target ];
            $allowedArray = explode(',', $allowedAccessString);
            
            if(in_array($action, $allowedArray)){
                $isAllowed= true;
            }
        }
        
        return $isAllowed;
    }
    
    private function getFullClaims(string $host, array $claims ): array {
        $out= [];
        
        foreach($claims as $k=>$v){
            $urlSafe= $this->urlSafeDecode(urldecode($host.$k));
            $out[ $urlSafe ]= $v;
        }
        
        return $out;
    }
    
    private function getActionFromMethod(string $method): string {
        $access= '';
        
        if( $method == "GET"){
            $access= 'read';
        }else if( $method == "PUT"){
            $access= 'update';
        }else if( $method == "POST"){
            $access= 'create';
        }else {
            $access= strtolower($method);
        }

        return $access;
    }
    
    /*
    public function generateToken(string $iss, string $tokenType, ClientSession $session ){
        
        // 1. Check if the audience is authorized
        
        
        // 2. Generates a JWT token
        $t= new JWToken();
        
        $jwtH= new JWTHeader();
        $jwtH->setAlg(JWTHeader::$ALG_NONE);
        
        $jwtP= new JWTPayload();
        $jwtP->setAud($session->getAudience());
        $jwtP->setClientId($session->getClient()->getAppId());
        $jwtP->setIat(new \DateTime() );
        $jwtP->setJti( $this->getRandomString(256) );
        $jwtP->setIss( $iss );

        $timeoutDate = new \DateTime();
        $timeout = 60 * 60 ; // 1h token
        $timeoutDate->add(new \DateInterval("PT".$timeout."S"));
        $jwtP->setExp($timeoutDate); 
        $jwtP->setSub( $session->getUser()->getLogin() );
        
        $t->setHeader($jwtH);
        $t->setPayload($jwtP);
        
        $strToken= $this->getEncodedToken($t);
        
        $aToken= $this->generateTokenBasic($tokenType, $session);
        $aToken->setCode($strToken);
        $aToken->setEncoding(Token::$ENC_JWT);
        
        return $aToken;
    }
    */
    
    /**
     * Generation of a JWT Token
     * 
            BASE64URL(UTF8(JWS Protected Header)) || '.' ||
            BASE64URL(JWS Payload) || '.' ||
            BASE64URL(JWS Signature)
     * 
     * @param JWToken $token
     * @return type
     */
    public function getEncodedToken( JWToken $token, string $privateCert = null ){
        $out= '';
        
        if( $token->getHeader()->getAlg() == JWTHeader::$ALG_NONE){
            
            $out= $this->getTokenPlain($token);
            
        }else if( $token->getHeader()->getAlg() == JWTHeader::$ALG_HS256){
            
            $out= $this->getTokenHS256($token, $privateCert );
            
        }else if( $token->getHeader()->getAlg() == JWTHeader::$ALG_RS256){
            
            $out= $this->getTokenRS256($token, $privateCert );
        }
        
        return $out;
    }
    
    private function getTokenPlain(JWToken $token ): string {
        $header = $this->urlSafeB64Encode( utf8_encode( json_encode($token->getHeader()->serialize()) ) );
        $payload = $this->urlSafeB64Encode( json_encode($token->getPayload()->serialize()) );
        
        /*
        $this->codeVerifier = $this->urlSafeB64Encode(random_bytes(64));
        
        $strHash= hash("SHA256", $this->codeVerifier, true);
        $str64= $this->urlSafeB64Encode($strHash);
        $this->codeChallenge= $str64;
        */
        
        return $header.".".$payload;
    }
    
    private function getTokenHS256(JWToken $token, string $secret ): string {
        
        $signature = $this->hashHMAC($secret, $this->getTokenPlain($token) );
        
        return $this->getTokenPlain($token).".".$signature;
    }
    
    private function getTokenRS256(JWToken $token, string $privateCert  ): string {
        
        $signature = $this->signRS256($privateCert, '', $this->getTokenPlain($token));
        
        return $this->getTokenPlain($token).".".$signature;
    }
    

    private function generateDigest($content): string {
        // Redsys - Primero hacemos el base64 del contenido
        // Step 0 de la guia:
        // - base64
        // Validado con ejemplo de la guia No se codifica en base64 la entrada.
        //$content64= base64_encode($content);
        
        // Step 1: 
        // - Creamos hash con retorno en base64
        // - https://caligatio.github.io/jsSHA/
        // Validado con ejemplo de la guia. true -> binary output
        $hashOut= openssl_digest ($content , "sha256", true); 
        $out= $this->urlSafeB64Encode($hashOut);
        
        return $out;
    }

    private function hashHMAC(string $key, string $content): string {
        
        $out= $this->urlSafeB64Encode( hash_hmac( "sha256", $content, $key, true) );
        
        return $out;
    }
    
    private function signRS256(string $key, string $pass, string $content): string {
        $signedContent= null;
        $signRes= false;
        
        $keyRes= openssl_get_privatekey($key);
        
        if( $keyRes != false ) {
            $signRes= openssl_sign($content, $signedContent, $keyRes, OPENSSL_ALGO_SHA256 ); // ($content , "sha256", true); 
        }        
        if( $signRes ){
            $out= $this->urlSafeB64Encode($signedContent);
        }else {
            $out= openssl_error_string();
        } 
        return $out;
    }
    
    public function urlSafeDecode($b64): string
    {
        $b64 = str_replace('-','+', $b64);
        $b64 = str_replace('_','/', $b64);
        
        return urldecode($b64);
    }  
    
    public function urlSafeEncode($b64): string
    {
        $b64 = str_replace('+','-', $b64);
        $b64 = str_replace('/','_', $b64);
        
        return urlencode($b64);
    }  
    
    /**
     * 
     * Appendix A: IETF 7636
     * 
        static string base64urlencode(byte [] arg)
        {
          string s = Convert.ToBase64String(arg); // Regular base64 encoder
          s = s.Split('=')[0]; // Remove any trailing '='s
          s = s.Replace('+', '-'); // 62nd char of encoding
          s = s.Replace('/', '_'); // 63rd char of encoding
          return s;
        }
     * 
     * @param type $data
     * @return string
     */
    
    /**
    * base64url encoding.
    * @param  String $input    Data to be encoded. 
    * @param  Int    $nopad    Whether "=" pad the output or not. 
    * @param  Int    $wrap     Whether to wrap the result. 
    * @return base64url encoded $input. 
    */
   private function urlSafeB64Encode($input,$nopad=1,$wrap=0)
   {
       $data  = base64_encode($input);

       if($nopad) {
           $data = str_replace("=","",$data);
       }
       $data = strtr($data, '+/=', '-_,');
       if ($wrap) {
           $datalb = ""; 
           while (strlen($data) > 64) { 
               $datalb .= substr($data, 0, 64) . "\n"; 
               $data = substr($data,64); 
           } 
           $datalb .= $data; 
           return $datalb; 
       } else {
           return $data;
       }
   }

    /*
    public function urlSafeB64Encode($data): string
    {
        $b64 = base64_encode($data);
        $b64 = explode('=', $b64)[0];
        $b64 = str_replace('+','-', $b64);
        $b64 = str_replace('/','_', $b64);
        
        return $b64;
    }
    */
    private function urlSafeB64Decode($b64): string
    {
        $b64 = str_replace('-','+', $b64);
        $b64 = str_replace('_','/', $b64);
        
        return base64_decode($b64);
    }  
    
    public function getRandomString($size) { 
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'; 
        return $this->getRandomData($size, $characters);
    }
    
    public function getRandomData($size, $source) { 
        $characters = $source;
        $randomString = ''; 

        for ($i = 0; $i < $size; $i++) { 
            $index = rand(0, strlen($characters) - 1); 
            $randomString .= $characters[$index]; 
        } 

        return $randomString; 
    }
     
}