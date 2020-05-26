<?php

namespace BeyondBlueSky\LibJWT\Entity;

use BeyondBlueSky\LibJWT\Entity\Serializable;

class JWTPayload implements Serializable {

    /**
     * iss: from the word issuer. A case-sensitive string or URI that uniquely identifies the party that issued the JWT. Its interpretation is application specific (there is no central authority managing issuers).
     * 
     * @Var(type="string", length=255)
     */
    private $iss;

    /**
     * sub: from the word subject. A case-sensitive string or URI that uniquely identifies the party that this JWT carries information about. In other words, the claims contained in this JWT are statements about this party. The JWT spec specifies that this claim must be unique in the context of the issuer or, in cases where that is not possible, globally unique. Handling of this claim is application specific.
     * 
     * @Var(type="string", length=255)
     */
    private $sub;

    /**
     * exp: from the word expiration (time). A number representing a specific date and time in the 6 format “seconds since epoch” as defined by POSIX . This claims sets the exact moment from
     * which this JWT is considered invalid. Some implementations may allow for a certain skew between clocks (by considering this JWT to be valid for a few minutes after the expiration date).
     * 
     * @Var(type="datetime")
     */
    private $exp;

    /**
     * aud: from the word audience. Either a single case-sensitive string or URI or an array of such values that uniquely identify the intended recipients of this JWT. In other words, when this claim is present, the party reading the data in this JWT must find itself in the aud claim or disregard the data contained in the JWT. As in the case of the iss and sub claims, this claim is application specific.
     * 
     * @Var(type="string", length=255)
     */
    private $aud;

    /**
     * iat: from issued at (time). A number representing a specific date and time (in the same format as exp and nbf ) at which this JWT was issued.
     * 
     * @Var(type="datetime")
     */
    private $iat;

    /**
     * jti: from JWT ID. A string representing a unique identifier for this JWT. This claim may be used to differentiate JWTs with other similar content (preventing replays, for instance). It is up to the implementation to guarantee uniqueness.     * 
     * 
     * @Var(type="string", length=1024)
     */
    private $jti;

    /**
     * @Var(type="string", length=1024)
     */
    private $client_id;

    private $publicClaims = [
        'iss',
        'sub',
        'exp',
        'aud',
        'iat',
        'jti',
        'client_id',
        'publicClaims',
    ];
    
    
    public function serialize(): array {
        $out= (array) $this;
        $out['iat']= $this->iat->format( \DateTimeInterface::ISO8601 );
        $out['exp']= $this->exp->format( \DateTimeInterface::ISO8601 );
        $out= $this->cleanUpSerialize($out);       
        return $out;
    }
    
    public function unserialize(array $objectArray) {
        foreach($objectArray as $idx=>$val){
            if( $idx == 'iat' || $idx == 'exp' ){
                $this->$idx= \DateTime::createFromFormat(  \DateTimeInterface::ISO8601 , $val);
            }else {
                $this->$idx= $val;
            }
        }
    }
    
    private function cleanUpSerialize(array $a){
        $out= [];
        foreach($a as $k=>$v){
            $k = preg_replace('/[\x00-\x1F\x7F-\xFF]/', '', $k);
            $k2= str_replace('BeyondBlueSky\LibJWT\Entity\JWTPayload', '', $k);
            $out[$k2]= $v;
        }
        
        return $out;
    }

    public function restore(string $payloadString){
        $decoded = json_decode( base64_decode($payloadString) );
        
        $this->unserialize( (array)$decoded);
        
        //var_dump($decoded);
    }

    public function getIss(): ?string
    {
        return $this->iss;
    }

    public function setIss(string $iss): self
    {
        $this->iss = $iss;

        return $this;
    }

    public function getSub(): ?string
    {
        return $this->sub;
    }

    public function setSub(string $sub): self
    {
        $this->sub = $sub;

        return $this;
    }

    public function getExp(): ?\DateTimeInterface
    {
        return $this->exp;
    }

    public function setExp(\DateTimeInterface $exp): self
    {
        $this->exp = $exp;

        return $this;
    }

    public function getAud(): ?string
    {
        return $this->aud;
    }

    public function setAud(string $aud): self
    {
        $this->aud = $aud;

        return $this;
    }

    public function getClientId(): ?string
    {
        return $this->client_id;
    }

    public function setClientId(string $client_id): self
    {
        $this->client_id = $client_id;

        return $this;
    }

    public function getIat(): ?\DateTimeInterface
    {
        return $this->iat;
    }

    public function setIat(\DateTimeInterface $iat): self
    {
        $this->iat = $iat;

        return $this;
    }

    public function getJti(): ?string
    {
        return $this->jti;
    }

    public function setJti(string $jti): self
    {
        $this->jti = $jti;

        return $this;
    }    
    
    public function addClaim(string $key, string $claim){
        $this->$key = $claim;
        
        return $this;
    }
    
    public function getClaims(){
        $out= [];
        
        $vals = (array) $this;
        $vals = $this->cleanUpSerialize($vals);
        
        foreach($vals as $key=>$val){
            if( ! in_array($key, $this->publicClaims ) ){
                $out[$this->urlSafeDecode($key)]= $this->urlSafeDecode($val);
            }
        }
        
        return $out;
    }
    
    /**
    * base64url encoding.
    * @param  String $input    Data to be encoded. 
    * @param  Int    $nopad    Whether "=" pad the output or not. 
    * @param  Int    $wrap     Whether to wrap the result. 
    * @return base64url encoded $input. 
    */
   private function urlSafeEncode($input,$nopad=1,$wrap=0)
   {
       $b64 = str_replace('+','-', $input);
       $b64 = str_replace('/','_', $b64);
        
       return $b64;
       
   }

    /*
    public function urlSafeB64Encode($data): string
    {
        $b64 = str_replace('+','-', $b64);
        $b64 = str_replace('/','_', $b64);
        
        return $b64;
    }
    */
    private function urlSafeDecode($b64): string
    {
        $b64 = str_replace('-','+', $b64);
        $b64 = str_replace('_','/', $b64);
        
        return $b64;
    }  
    
}