<?php

namespace BeyondBlueSky\LibJWT\Entity;

interface Serializable {
    
    public function serialize(): array ;
    
    public function unserialize(array $objectArray);

}
