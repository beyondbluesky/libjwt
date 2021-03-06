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

use BeyondBlueSky\LibJWT\Entity\Exception\JWTokenSignatureException;

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
    
    public function signedToken(string $token): bool{
        $tokenArray = explode('.', $token);
        if( sizeof($tokenArray) < 3 ){
            return false;
        }else {
            return true;
        }
    }
    
    public function tokenVerified(string $token, string $publicKey ): bool{
        
        $tokenArray = explode('.', $token);
        if( sizeof($tokenArray) < 3 ){
            throw new JWTokenSignatureException('JWT without signature');
        }
        $data = $tokenArray[0].".".$tokenArray[1];
        $signature = $this->urlSafeB64Decode($tokenArray[2]);
        
        $result = openssl_verify($data, $signature, $publicKey, OPENSSL_ALGO_SHA256 );
        
        $boolRes = ($result == 1)? true: false;
        
        if( $result == -1 ){
            throw new JWTokenSignatureException('LibJWT internal error verifying signature.');
        }
        
        return $boolRes;
    }

    public function getClaims(JWToken $jwToken){
        $claims = $jwToken->getClaims();
        $claims = $this->getFullClaims($jwToken->getIss(), $claims);
        
        return $claims;
    }
    
    public function getPaths(JWToken $jwToken){
        $claims = $this->getClaims($jwToken);
        $claims = $this->getPaths0($claims);
        
        return $claims;
    }
    
    public function getActionFromMethod(string $method): string {
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
    
    public function inClaims(JWToken $jwToken, string $target, string $method ){
        $isAllowed= false;
        
        $action = $this->getActionFromMethod( $method );
        $claims = $this->getPaths($jwToken);
        
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
    
    /**
     * Private method that looks for the paths of the claims, supporting basic 
     * and multi-level claims.
     * 
     * @param array $claims
     * @return array
     */
    private function getPaths0(array $claims){
        $out=[];
        
        foreach($claims as $k=>$v){
            if( $v != null ){
                // Compounded claims
                $vArray = (array) $v;
                $vArray = (array) $vArray[0];
                foreach($vArray as $k2=> $v2){
                    $v2Array = (array) $v2;
                    $v2Array = (array) json_decode($v2Array[0]);
                    foreach($v2Array as $k3=>$v3){
                        if( $k3 == 'path'){
                            $out = (array)$v3; 
                        }
                    }
                }
            }else {
                // Simple 
                $urlSafe= $this->urlSafeDecode(urldecode($host.$k));
                $out[ $k ]= $v;
            }
        }
        
        return $out;
    }
    
    /**
     * It adds a full domain to each claim it receives. There are 2 types of claims: simple and compounded ones.
     * The simple claims are like following:
     * {
     *  "dom":"Manager",
     *  "\/api\/bankaccount\/":"create,list,delete,update,read",
     *  "\/api\/bank\/":"create,list,delete,update,read,status",
     *  "\/api\/bankaccounts\/":"create,list,delete,update,read",
     *  "\/api\/psd2\/oauth\/connect":"read","\/api\/psd2\/oauth\/check":"read",
     *  "\/api\/bank\/consent":"create,read,status",
     *  "roles":"[\"DEV\/WRITER\"]"
     * }
     * 
     * The compounded ones follow:
     * {
     *  "dom.1":"{
     *      \"dom\":\"0000+0001\",
     *      \"nam\":\"LOCAL\",
     *      \"path\":{
     *          \"\\\/api\\\/admin\\\/server\":\"create,delete,update,read\",
     *          \"\\\/api\\\/security\\\/user\":\"create,delete,update,read\",
     *          \"\\\/api\\\/security\\\/user\\\/me\":\"create,delete,update,read\"
     *      },
     *      \"roles\":\"[\\\"ROLE\/SUPERADMIN\\\"]\"
     *  }"
     * }
     * 
     * @param string $host
     * @param array $claims
     * @return array
     */
    public function getFullClaims(string $host, array $claims ): array {
        $out= [];
        
        foreach($claims as $k=>$v){
            $vObj= json_decode($v);
            if( $vObj != null ){
                // Compounded claims
                $out[$k]= new \stdClass();
                
                $vArray = (array) $vObj;
                foreach($vArray as $k2=> $v2){
                    $v2Array = (array) $v2;
                    if( $k2 == 'path'){
                        
                        $out[$k]->$k2 = $this->getFullClaimsSimple($host, $v2Array);
                        
                    }else {
                        
                        $out[$k]->$k2 = $v2;
                    }
                }
            }else {
                // Simple 
                $urlSafe= $this->urlSafeDecode(urldecode($host.$k));
                $out[ $urlSafe ]= $v;
            }
        }
        return $out;
    }
    
    private function getFullClaimsSimple(string $host, array $claims ): array {
        $out= [];
        
        foreach($claims as $k=>$v){
            $urlSafe= $this->urlSafeDecode(urldecode($host.$k));
            $out[ $urlSafe ]= $v;
        }
        
        return $out;
    }
    
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