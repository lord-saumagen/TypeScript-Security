/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {


    /**
    * @class TS.Security.SHA224
    *
    * @classdesc This class implements the SAH224 hash algorithm as described in the nist publication
    *  'FIPS PUB 180-4, Secure Hash Standard (SHS)'.
    *
    *  @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | NIST }
    */
    export class SHA224 extends TS.Security.Cryptography
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

      /** 
      * @private
      */
      private hash5: number;

      /** 
      * @private
      */
      private hash6: number;

      /** 
      * @private
      */
      private hash7: number;


      //
      // Define the for constants as described in 
      // http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | SHA-224 and SHA-256 Constants
      //
      /** 
      * @private
      */
      private roundConstantArray: Array<number>

      constructor()
      {
        super();
      }


      /**
      * @descriptions Initializes the hash values and the round constant array.
      *
      * @private
      */
      private initialize() : void
      {
        //
        // Initialize the hash values
        //
        this.hash0 = 0xc1059ed8;
        this.hash1 = 0x367cd507;
        this.hash2 = 0x3070dd17;
        this.hash3 = 0xf70e5939;
        this.hash4 = 0xffc00b31;
        this.hash5 = 0x68581511;
        this.hash6 = 0x64f98fa7;
        this.hash7 = 0xbefa4fa4;

        //
        // Initialize the round constants
        //
        this.roundConstantArray = TS.Security.getSHA224_256RoundConstants();
      }


      /**
      * @description Encrypts the plain text given in argument 'message' and returns the digest / SHA224 hash as a
      *  hexadecimal string.
      *
      * @param {string | Array<number>} message, Either a simple text string or an array of unsigned byte values.
      * @returns {string}, The resulting digest / SHA224 as HEX string.
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      public encrypt(message: string | Array<number>): string
      {
        let wordArray: Array<number>;
        let index: number;
        let blockIndex: number;
        let temp1: number;
        let temp2: number;
        let resultString: string;

        //
        // Define the working variables
        //
        let _a: number;
        let _b: number;
        let _c: number;
        let _d: number;
        let _e: number;
        let _f: number;
        let _g: number;
        let _h: number;

        //
        // Define the array of message schedule variables.
        //
        let _w: Array<number>;


        if (TS.Utils.Assert.isNullOrUndefined(message))
        {
          throw new TS.ArgumentNullOrUndefinedException("message", "Argument message must be null or undefined in function 'TS.Security.SHA224.encrypt'.");
        }//END if

        if (!TS.Utils.Assert.isString(message) && !TS.Utils.Assert.isUnsignedByteArray(message))
        {
          throw new TS.InvalidTypeException("message", message, "Argument message must be a valid string or an array of unsigned byte values in function 'TS.Security.SHA224.encrypt'.");
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
        _w = new Array<number>(63);

        for (blockIndex = 0; blockIndex < wordArray.length; blockIndex += 16)
        {
          //
          // Prepare the message schedul
          //
          for (index = 0; index < 16; index++)
          {
            _w[index] = wordArray[blockIndex + index];
          }//END of

          for (index = 16; index <= 64; index++)
          {
            temp1 = (TS.Security.Cryptography.gamma1_32(_w[index - 2]) + _w[index - 7]) % 0x100000000;
            temp2 = (TS.Security.Cryptography.gamma0_32(_w[index - 15]) + _w[index - 16]) % 0x100000000;
            _w[index] = (temp1 + temp2) % 0x100000000; 
          }//END for

          //
          // Initialize the working variables
          //
          _a = this.hash0;
          _b = this.hash1;
          _c = this.hash2;
          _d = this.hash3;
          _e = this.hash4;
          _f = this.hash5;
          _g = this.hash6;
          _h = this.hash7;

          for (index = 0; index < 64; index++)
          {
            if (index == 17)
            {
              var X = 10;
            }//END if

            temp1 = (_h + TS.Security.Cryptography.sigma1_32(_e) + TS.Security.Cryptography.ch32(_e, _f, _g) + this.roundConstantArray[index] + _w[index]) % 0x100000000;
            temp2 = (TS.Security.Cryptography.sigma0_32(_a) + TS.Security.Cryptography.maj32(_a, _b, _c)) % 0x100000000;
            restOperation();

          }//END for

          function restOperation()
          {
            _h = _g;
            _g = _f;
            _f = _e;
            _e = (_d + temp1) % 0x100000000;
            _d = _c;
            _c = _b;
            _b = _a;
            _a = (temp1 + temp2) % 0x100000000;
          }

          this.hash0 = (this.hash0 + _a) % 0x100000000;
          this.hash1 = (this.hash1 + _b) % 0x100000000;
          this.hash2 = (this.hash2 + _c) % 0x100000000;
          this.hash3 = (this.hash3 + _d) % 0x100000000;
          this.hash4 = (this.hash4 + _e) % 0x100000000;
          this.hash5 = (this.hash5 + _f) % 0x100000000;
          this.hash6 = (this.hash6 + _g) % 0x100000000;
          this.hash7 = (this.hash7 + _h) % 0x100000000;

        }//END for

        resultString = TS.Utils.UInt32ToHexString(this.hash0) +
          TS.Utils.UInt32ToHexString(this.hash1) +
          TS.Utils.UInt32ToHexString(this.hash2) +
          TS.Utils.UInt32ToHexString(this.hash3) +
          TS.Utils.UInt32ToHexString(this.hash4) +
          TS.Utils.UInt32ToHexString(this.hash5) +
          TS.Utils.UInt32ToHexString(this.hash6);
        return resultString;
      }

    }//END class

  }//END namespace
}//END namespace 