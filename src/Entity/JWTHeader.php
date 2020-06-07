<?php

/* 
 * The Creative Commons BY-NC-SA 4.0 License
 * Attribution-NonCommercial-ShareAlike 4.0 International
 * Josep Llauradó Selvas
 * pep@beyondbluesky.com
 * 
 * 
*/


namespace BeyondBlueSky\LibJWT\Entity;

use BeyondBlueSky\LibJWT\Entity\Serializable;

class JWTHeader implements Serializable {

    /*
     */
    public static $ALG_NONE  = 'none';

    public static $ALG_HS256 = 'HS256';
    /*
     * HMAC using SHA-256, called HS256 in the JWA spec.
     * 
     * For HMAC-based signing algorithms:
        const encodedHeader = base64(utf8(JSON.stringify(header)));
        const encodedPayload = base64(utf8(JSON.stringify(payload))); const signature = base64(hmac(`${encodedHeader}.${encodedPayload}`,
        secret, sha256));
        const jwt = `${encodedHeader}.${encodedPayload}.${signature}`;
     */
        
    public static $ALG_RS256 = 'RS256';
    /*
     * RSASSA PKCS1 v1.5 using SHA-256, called RS256 in the JWA spec.
     * 
        const encodedHeader = base64(utf8(JSON.stringify(header)));
        const encodedPayload = base64(utf8(JSON.stringify(payload)));
        const signature = base64(rsassa(`${encodedHeader}.${encodedPayload}`,
        privateKey, sha256));
        const jwt = `${encodedHeader}.${encodedPayload}.${signature}`;
     */
    
     /* 
     * ECDSA using P-256 and SHA-256, called ES256 in the JWA spec.
     */
    
    private $alg;
    private $typ;
    
    public function __construct() {
        $this->typ = 'at+jwt';
        
    }
    
    public function getAlg(): string {
        return $this->alg;
    }
    
    public function setAlg(string $alg){
        $this->alg = $alg;
    }
    
    public function serialize(): array {
        $out= (array) $this;
        
        $out= $this->cleanUpSerialize($out);
        
        return $out;
    }
    
    public function unserialize(array $objectArray) {
        foreach($objectArray as $idx=>$val){
            $this->$idx= $val;
        }
    }
    
    private function cleanUpSerialize(array $a){
        $out= [];
        foreach($a as $k=>$v){
            $k = preg_replace('/[\x00-\x1F\x7F-\xFF]/', '', $k);
            $k2= str_replace('BeyondBlueSky\LibJWT\Entity\JWTHeader', '', $k);
            $out[$k2]= $v;
        }
        
        return $out;
    }
    
    public function restore(string $headerString){
        $decoded = json_decode( base64_decode($headerString));
        
        $this->unserialize( (array)$decoded);
        
        //var_dump($decoded);
    }
}
