<?php

namespace BeyondBlueSky\LibJWT\Entity;

use BeyondBlueSky\LibJWT\Entity\JWTHeader;
use BeyondBlueSky\LibJWT\Entity\JWTPayload;

use BeyondBlueSky\LibJWT\Entity\Exception\NotJWTokenException;

class JWToken {

    /**
     *
     * @var JWTHeader
     */
    private $header;

    /**
     *
     * @var JWTPayload
     */
    private $payload;
    
    public function getHeader(): JWTHeader {
        return $this->header;
    }
    
    public function setHeader(JWTHeader $header){
        $this->header = $header;
    }
    
    public function getPayload(): JWTPayload {
        return $this->payload;
    }
    
    public function setPayload(JWTPayload $payload ){
        $this->payload = $payload;
    }
      
    public function restore(string $tokenString){
        $this->header = new JWTHeader();
        $this->payload = new JWTPayload();
        
        $tokenArray = explode('.', $tokenString);
        
        if( sizeof($tokenArray) < 2 ){
            throw new NotJWTokenException('Token is not a JWToken');
        }

        $this->header->restore($tokenArray[0]);
        $this->payload->restore($tokenArray[1]);
        
        return $this;
    }
    
    public function isExpired(){
        $now = new \DateTime();
        $due= $this->payload->getExp();
        
        if( $now->diff($due)->invert === 0 ){
            return false;
        }else {
            return true;
        }
    }
    
    public function getClaims(){
        return $this->payload->getClaims();
    }
    
    public function getAud(){
        return $this->payload->getAud();
    }
    
    public function getIss(){
        return $this->payload->getIss();
    }
}
