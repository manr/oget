/*******************************************************************************
 * oget (https://github.com/manr/oget)
 * 
 * Copyright (c) 2014 United Planet GmbH
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     United Planet GmbH
 *******************************************************************************/


/*
 * Package ksh implements the keyed salted hashing function
 * required for Intrexx authentication.
 */
package ksh


import (
	"crypto/sha1"
	"hash"
)


type KeyedSaltedHashing struct {
	hash.Hash
}


func NewSha1() *KeyedSaltedHashing {
	return &KeyedSaltedHashing{sha1.New()}
}


func (ksh *KeyedSaltedHashing) MakeDigest(pwd, salt, key []byte) []byte {
	ksh.Hash.Reset()
	ksh.Hash.Write(pwd)
	ksh.Hash.Write(salt)
	hashedPwd := ksh.Hash.Sum(nil)

	ipad  := make([]byte, 64)
	opad  := make([]byte, 64)

	for i:=0; i < 64; i++ {
		ipad[i] = byte(0x36)
		opad[i] = byte(0x5C)
	}

	for i:=0; i < len(hashedPwd); i++ {
		ipad[i] ^= hashedPwd[i]
		opad[i] ^= hashedPwd[i]
	}

	ksh.Hash.Reset()
	ksh.Hash.Write(ipad)
	ksh.Hash.Write(key)
	arTmp := ksh.Hash.Sum(nil)

	ksh.Hash.Reset()
	ksh.Hash.Write(opad)
	ksh.Hash.Write(arTmp)

	digest := ksh.Hash.Sum(nil)

	return digest
}

