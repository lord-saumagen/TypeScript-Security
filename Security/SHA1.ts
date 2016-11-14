/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {


    /**
    * @class TS.Security.SHA1
    *
    * @classdesc This class implements the SHA1 hash algorithm as described in the nist publication
    *  'FIPS PUB 180-4, Secure Hash Standard (SHS)'.
    *
    * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | NIST }
    */
    export class SHA1 extends Cryptography
    {
      //
      // Define the hash values
      //
      /** 
      * @private
      */
      private hash0: number;

      /**
      * @private
      */
      private hash1: number;

      /**
      * @private
      */
      private hash2: number;

      /**
      * @private
      */
      private hash3: number;

      /**
      * @private
      */
      private hash4: number;

      //
      // Define the for round constants as defined in
      // http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.2.1 SHA-1 Constants
      //
      /** 
      * @private
      */
      private roundConstant0: number;

      /**
      * @private
      */
      private roundConstant1: number;

      /**
      * @private
      */
      private roundConstant2: number;

      /**
      * @private
      */
      private roundConstant3: number;

      //TODO: Create the test functions. Add descripion
      /**
      * @constructor
      */
      constructor()
      {
        super();
      }


      /**
      * @descriptions Initializes the hash values and the round constants.
      *
      * @private
      */
      private initialize()
      {
        //
        // Initialize the hash values
        //
        this.hash0 = 0x67452301;
        this.hash1 = 0xEFCDAB89;
        this.hash2 = 0x98BADCFE;
        this.hash3 = 0x10325476;
        this.hash4 = 0xC3D2E1F0;

        //
        // Initialize the round constants
        //
        this.roundConstant0 = 0x5a827999;
        this.roundConstant1 = 0x6ed9eba1;
        this.roundConstant2 = 0x8f1bbcdc;
        this.roundConstant3 = 0xca62c1d6;
      }

      /**
      * @description Encrypts the plain text given in argument 'message' and returns the digest / SHA1 hash as a
      *  hexadecimal string.
      *
      * @param {string | Array<number>} message, Either a simple text string or an array of unsigned byte values.
      *
      * @returns {string}, The resulting digest / SHA1 as HEX string.
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      public encrypt(message: string | Array<number>): string
      {
        let wordArray: Array<number>;
        let index: number;
        let blockIndex: number;
        let temp: number;
        let resultString: string;


        //
        // Define the working variables
        //
        let _a: number;
        let _b: number;
        let _c: number;
        let _d: number;
        let _e: number;

        //
        // Define the array of message schedule variables.
        //
        let _w: Array<number>;

        if (TS.Utils.Assert.isNullOrUndefined(message))
        {
          throw new TS.ArgumentNullOrUndefinedException("message", "Argument message must be null or undefined in function 'TS.Security.SHA1.encrypt'.");
        }//END if

        if (!TS.Utils.Assert.isString(message) && !TS.Utils.Assert.isUnsignedByteArray(message))
        {
          throw new TS.InvalidTypeException("message", message, "Argument message must be a valid string or an array of unsigned byte values in function 'TS.Security.SHA1.encrypt'.");
        }//END if

        //
        // Pad the message
        //
        wordArray = TS.Security.pad_SHA(message);

        //
        // Initialize constants and hash values.
        //
        this.initialize();

        //
        // Initialize the array of message schedule variables.
        //
        _w = new Array<number>(80);

        for (blockIndex = 0; blockIndex < wordArray.length; blockIndex += 16)
        {
          //
          // Prepare the message schedul
          //
          for (index = 0; index < 16; index++)
          {
            _w[index] = wordArray[blockIndex + index];
          }//END of

          for (index = 16; index <= 79; index++)
          {
            _w[index] = SHA1.rotateLeft32(SHA1.correctNegative(_w[index - 3] ^ _w[index - 8] ^ _w[index - 14] ^ _w[index - 16]), 1);
          }//END for

          //
          // Initialize the working variables
          //
          _a = this.hash0;
          _b = this.hash1;
          _c = this.hash2;
          _d = this.hash3;
          _e = this.hash4;

          //ch
          for (index = 0; index <= 19; index++)
          {
            temp = (SHA1.rotateLeft32(SHA1.correctNegative(_a), 5) + SHA1.ch32(_b, _c, _d) + _e + this.roundConstant0 + _w[index]) % 0x100000000;
            restOperation();
          }//END for

          //parity
          for (index = 20; index <= 39; index++)
          {
            temp = (SHA1.rotateLeft32(SHA1.correctNegative(_a), 5) + SHA1.parity(_b, _c, _d) + _e + this.roundConstant1 + _w[index]) % 0x100000000;
            restOperation();
          }

          //maj
          for (index = 40; index <= 59; index++)
          {
            temp = (SHA1.rotateLeft32(SHA1.correctNegative(_a), 5) + SHA1.maj32(_b, _c, _d) + _e + this.roundConstant2 + _w[index]) % 0x100000000;
            restOperation();
          }

          //parity
          for (index = 60; index <= 79; index++)
          {
            temp = (SHA1.rotateLeft32(SHA1.correctNegative(_a), 5) + SHA1.parity(_b, _c, _d) + _e + this.roundConstant3 + _w[index]) % 0x100000000;
            restOperation();
          }

          function restOperation()
          {
            _e = _d;
            _d = _c;
            _c = SHA1.rotateLeft32(SHA1.correctNegative(_b), 30) % 0x100000000;
            _b = _a;
            _a = temp;
          }

          this.hash0 = (this.hash0 + _a) % 0x100000000;
          this.hash1 = (this.hash1 + _b) % 0x100000000;
          this.hash2 = (this.hash2 + _c) % 0x100000000;
          this.hash3 = (this.hash3 + _d) % 0x100000000;
          this.hash4 = (this.hash4 + _e) % 0x100000000;

        }//END for

        resultString = TS.Utils.UInt32ToHexString(this.hash0) +
          TS.Utils.UInt32ToHexString(this.hash1) +
          TS.Utils.UInt32ToHexString(this.hash2) +
          TS.Utils.UInt32ToHexString(this.hash3) +
          TS.Utils.UInt32ToHexString(this.hash4);
        return resultString;
      }

    }//END class

  }//END namespace
}//END namespace 