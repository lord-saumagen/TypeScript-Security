/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {

    interface IPseudoRandomFunctionDescriptor
    {
      outputBlockSizeInByte: number;
      random(key: Array<number>, data: Array<number>): Array<number>;
    }

    //https://tools.ietf.org/html/rfc6070 (PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2))
    //https://tools.ietf.org/pdf/rfc2898.pdf (PKCS #5: Password-Based Cryptography Specification Version 2.0)
    //http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf (800-132 Recommendation for Password- Based Key Derivation)

    /**
    * @description This is an implementation of the PBKDF2 (Password-Based Key Derivation Function 2) as described in
    *  RFC 2898.
    *
    * @param { Array<number>} password, A password in the form of a byte array.
    * @param { Array<number>} salt, A salt in the form of a byte array.
    * @param {number} iterations, The number of iteration which should take place to generate the derived key.
    * @param {number} requiredDerivedKeyLengthInByte, The required lenght of the derive key in byte.
    * @param {IPseudoRandomFunctionDescriptor} pseudoRandomFunctionDescriptor, A random function descriptor which has
    *  information about the random function output block size and a 'random' function which takes two byte arrays
    *  and returns a byte array of random byte values. That byte array has the length specified in the block size
    *  info. 
    *
    * @returns {Array<number>}, The derived key.
    *
    * @throws {TS.ArgumentOutOfRangeException}
    */
    function PBKDF2(password: Array<number>, salt: Array<number>, iterations: number, requiredDerivedKeyLengthInByte: number, pseudoRandomFunctionDescriptor: IPseudoRandomFunctionDescriptor): Array<number>
    {
      /**
       * @description The resulting derived key after derivation.
       */
      let derivedKey: Array<number>;


      /**
      * @description An array of output blocks comming from the pseudo random function. The total number of bytes in
      *  that array must be greater or equal to the 'requiredDerivedKeyLengthInByte'.
      *
      * @see blocksPerDerivedKey
      */
      let derivedKeyBlocksArray: Array<Array<number>>;

      /**
      * @description The number of blocks needed to get enough bytes to satisfy the 'requiredDerivedKeyLengthInByte'.
      *  It is the maximum lenght of the 'derivedKeyBlocksArray'.
      *
      *  blocksPerDerivedKey * pseudoRandomFunctionDescriptor.outputBlockSizeInByte >= requiredDerivedKeyLengthInByte
      *
      * @see derivedKeyBlocksArray
      */
      let blocksPerDerivedKey: number;

      let index: number;

      TS.Utils.checkUByteArrayParameter("password", password, "TS.Security.PBKDF2");
      TS.Utils.checkUByteArrayParameter("salt", salt, "TS.Security.PBKDF2");
      TS.Utils.checkUIntNumberParameter("requiredDerivedKeyLengthInByte", requiredDerivedKeyLengthInByte, "TS.Security.PBKDF2");
      TS.Utils.checkParameter("pseudoRandomFunctionDescriptor", pseudoRandomFunctionDescriptor, "TS.Security.PBKDF2");

      //
      // RFC 2898, 5.2 PBKDF2, Step 1
      //
      // 1. If dkLen > (2 ^ 32 - 1) * hLen, output "derived key too long" and stop.
      //
      if (requiredDerivedKeyLengthInByte > 0xFFFFFFFF)
      {
        throw new TS.ArgumentOutOfRangeException("requiredDerivedKeyLengthInByte", requiredDerivedKeyLengthInByte, "The value of 'requiredDerivedKeyLengthInByte' exceeds the maximum value which is 0xFFFFFFFF in function 'TS.Security.PBKDF2'.");
      }

      //
      // RFC 2898, 5.2 PBKDF2, Step 2
      //
      // 2. Let l be the number of hLen- octet blocks in the derived key, rounding up, and let r be the number of
      //    octets in the last block:
      //
      //      l = CEIL(dkLen / hLen),
      //      r = dkLen - (l - 1) * hLen.
      //

      //
      // l = CEIL(dkLen / hLen),
      //
      blocksPerDerivedKey = Math.ceil(requiredDerivedKeyLengthInByte / pseudoRandomFunctionDescriptor.outputBlockSizeInByte);


      //
      // RFC 2898, 5.2 PBKDF2, Step 3
      //
      // 3. For each block of the derived key apply the function F defined
      //    below to the password P, the salt S, the iteration count c, and
      //    the block index to compute the block:
      // 
      //      T_1 = F(P, S, c, 1),
      //      T_2 = F(P, S, c, 2),
      //              ...
      //      T_l = F(P, S, c, l),
      // 
      //    where the function F is defined as the exclusive- or sum of the
      //    first c iterates of the underlying pseudorandom function PRF
      //    applied to the password P and the concatenation of the salt S
      //    and the block index i:
      // 
      //      F(P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
      // 
      //    where
      // 
      //      U_1 = PRF(P, S || INT(i)),
      //      U_2 = PRF(P, U_1),
      //              ...
      //      U_c = PRF(P, U_{c-1 }).
      // 
      //    Here, INT(i) is a four- octet encoding of the integer i, most
      //    significant octet first.
      //

      derivedKeyBlocksArray = new Array<Array<number>>();

      for (index = 0; index < blocksPerDerivedKey; index++)
      {
        let data = salt.concat(TS.Utils.UInt32To4ByteArray(index + 1));
        derivedKeyBlocksArray[index] = iteratePseudoRandom(password, data, iterations, pseudoRandomFunctionDescriptor);
      }

      //
      // RFC 2898, 5.2 PBKDF2, Step 4
      //
      // 4. Concatenate the blocks and extract the first dkLen octets to
      //    produce a derived key DK:
      // 
      //      DK = T_1 || T_2 ||  ...  || T_l < 0..r - 1 >
      //

      derivedKey = new Array<number>();
      for (index = 0; index < derivedKeyBlocksArray.length; index++)
      {
        derivedKey.push(...derivedKeyBlocksArray[index]);
      }

      //
      // RFC 2898, 5.2 PBKDF2, Step 5
      //
      // 5. Output the derived key DK.
      //

      return derivedKey.slice(0, requiredDerivedKeyLengthInByte);
    }


    function iteratePseudoRandom(key: Array<number>, data: Array<number>, iterations: number, pseudoRandomFunctionDescriptor: IPseudoRandomFunctionDescriptor)
    {
      let tempData: Array<Array<number>>;
      let index: number;

      tempData = new Array<Array<number>>();

      for (index = 0; index < iterations; index++)
      {
        if (index == 0)
        {
          tempData[index] = pseudoRandomFunctionDescriptor.random(key, data);
        }
        else
        {
          tempData[index] = pseudoRandomFunctionDescriptor.random(key, tempData[index - 1]);
        }
      }

      return tempData.reduce((prev, curr, idx, arr) => 
      {
        return TS.Security.XORByteArray(prev, curr);
      });

    }


    export function PBKDF2_HMAC_SHA1(password: Array<number>, salt: Array<number>, iterations: number, requiredDerivedKeyLengthInByte: number) : Array<number>
    {

      function random(key: Array<number>, data: Array<number>): Array<number>
      {
        let hash = TS.Security.HMAC_SHA1(key, data);
        return TS.Utils.HexStringToUByteArray(hash);
      } 

      let pseudoRandomFunctionDescriptor: IPseudoRandomFunctionDescriptor = {
        outputBlockSizeInByte: 20,
        random: random
      };

      return PBKDF2(password, salt, iterations, requiredDerivedKeyLengthInByte, pseudoRandomFunctionDescriptor);
    }
  }
}