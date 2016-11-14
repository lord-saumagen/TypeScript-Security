/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {



    /**
    * @class TS.Security.Cryptography
    *
    * @descriptions This is the base class of the hash and crypto classes in the 'TS.Security' namespace. and
    *  implements some common used functions.
    */
    export class Cryptography
    {

      /**
      * @constructor
      *
      * @description Creates a new instance of the 'TS.Security.Cryptography' class.
      */
      public constructor()
      {
      }


      /**
      * @description Corrects a negative result which may occure after a bitoperation on a positive integer.
      *
      * @param {number} value, The value to correct.
      *
      * @returns {number}, The corrected value
      */
      protected static correctNegative(value: number): number
      {
        if (value < 0)
        {
          value = 0x100000000 + value;
        };
        return value;
      }

      // F(X,Y,Z) = XY v not(X) Z 
      protected static MD5FuncOne(roundB: number, roundC: number, roundD: number) : number
      {
        return TS.Security.Cryptography.correctNegative((roundB & roundC) | (~roundB & roundD));
      }

      // G(X,Y,Z) = XZ v Y not(Z) 
      protected static MD5FuncTwo(roundB: number, roundC: number, roundD: number): number
      {
        return TS.Security.Cryptography.correctNegative((roundB & roundD) | (roundC & ~roundD));
      }

      // H(X,Y,Z) = X xor Y xor Z
      protected static MD5FuncThree(roundB: number, roundC: number, roundD: number): number
      {
        return TS.Security.Cryptography.correctNegative((roundB ^ roundC ^ roundD));
      }

      //I(X, Y, Z) = Y xor (X v not(Z)) 
      protected static MD5FuncFour(roundB: number, roundC: number, roundD: number): number
      {
        return TS.Security.Cryptography.correctNegative(roundC ^ (roundB | ~roundD));
      }

      //TODO: Create the test functions.
      /**
      * @description This function excutes the XOR operation on the arguments 'firstWord' and 'secondWord' and returns
      *  the result as a byte array.
      *
      * @param {number} firstWord
      * @param {number} secondWord
      *
      * @throws {TS.InvalidTypeException}
      * @throws {TS.ArgumentException}
      *
      * @returns {Array<number>}
      */
      protected static xorWord(firstWord: Array<number>, secondWord: Array<number>): Array<number>
      {
        TS.Utils.checkUByteArrayParameter("data", firstWord, "TS.Security.Cryptography.xorWord");
        TS.Utils.checkUByteArrayParameter("data", secondWord, "TS.Security.Cryptography.xorWord");

        if (firstWord.length != 4)
        {
          throw new TS.ArgumentException("firstWord", firstWord, "Argument 'firstWord' has not the required length of 4 elements in function 'TS.Security.Cryptography.xorWord'.");
        }//END if

        if (secondWord.length != 4)
        {
          throw new TS.ArgumentException("secondWord", secondWord, "Argument 'secondWord' has not the required length of 4 elements in function 'TS.Security.Cryptography.xorWord'.");
        }//END if

        return [firstWord[0] ^ secondWord[0], firstWord[1] ^ secondWord[1], firstWord[2] ^ secondWord[2], firstWord[3] ^ secondWord[3]];
      }


      //TODO: Create the test functions.
      /**
      * @description Rotates the elements of the array given in argument 'data' leftwise for as many positions as given
      *  in argument 'positions'.
      *
      * @params {Array<any>} data, The array which will be rotated.
      * @params {number} positions, The number of positions to rotate.
      *
      * @returns {Array<any>}, The result array.
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      protected static rotateLeft(data: Array<any>, positions: number): Array<any>
      {
        var resultData: Array<any>;
        var index: number;
        var sourceIndex: number;

        TS.Utils.checkUIntNumberParameter("positions", positions, "TS.Security.Cryptography.rotateLeft");
        TS.Utils.checkArrayParameter("data", data, "TS.Security.Cryptography.rotateLeft");

        resultData = new Array<any>();

        for (index = 0; index < data.length; index++)
        {
          sourceIndex = (index + positions) % data.length;
          resultData.push(data[sourceIndex]);
        }//END for

        return resultData;
      }


      /**
      * @description Performs: (x & y) ^ (~x & z)
      *
      * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.1.1 SHA-1 Functions }
      *
      * @param {number} x
      * @param {number} y
      * @param {number} z
      *
      * @returns {number}
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      protected static ch32(x: number, y: number, z: number): number
      {
        TS.Utils.checkIntNumberParameter("x", x, "TS.Security.Cryptography.ch32");
        TS.Utils.checkIntNumberParameter("y", y, "TS.Security.Cryptography.ch32");
        TS.Utils.checkIntNumberParameter("z", z, "TS.Security.Cryptography.ch32");

        return TS.Security.Cryptography.correctNegative((x & y) ^ (~x & z));
      }


      //TODO: Create the test functions. Add descripion
      /**
      * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.1.1 SHA-1 Functions }
      *
      * @param {TS.TypeCode.UInt64} x
      * @param {TS.TypeCode.UInt64} y
      * @param {TS.TypeCode.UInt64} z
      *
      * @returns {TS.TypeCode.UInt64} 
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      protected static ch64(x: TS.TypeCode.UInt64, y: TS.TypeCode.UInt64, z: TS.TypeCode.UInt64): TS.TypeCode.UInt64
      {
        let tempMSInteger: number;
        let tempLSInteger: number;

        TS.Utils.checkUInt64NumberParameter("x", x, "TS.Security.Cryptography.ch64");
        TS.Utils.checkUInt64NumberParameter("y", y, "TS.Security.Cryptography.ch64");
        TS.Utils.checkUInt64NumberParameter("z", z, "TS.Security.Cryptography.ch64");

        tempMSInteger = this.ch32(x.mostSignificantInteger, y.mostSignificantInteger, z.mostSignificantInteger);
        tempLSInteger = this.ch32(x.leastSignificantInteger, y.leastSignificantInteger, z.leastSignificantInteger);

        return new TS.TypeCode.UInt64(tempMSInteger, tempLSInteger);
      }


      //TODO: Create the test functions.
      /**
      * @description Performs: (ror 7) ^ (ror 18) ^ (shr 3)
      *
      * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.1.2 SHA-224 and SHA-256 Functions }
      *
      * @param {number} x
      *
      * @returns {number}
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      protected static gamma0_32(x: number): number
      {
        TS.Utils.checkIntNumberParameter("x", x, "TS.Security.Cryptography.gamma0_32");

        return TS.Security.Cryptography.correctNegative(this.rotateRight32(x, 7) ^ this.rotateRight32(x, 18) ^ this.shiftRight32(x, 3));
      }


      //TODO: Create the test functions.
      /**
      * @description Performs: (ror 17) ^ (ror 19) ^ (shr 10)
      *
      * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.1.2 SHA-224 and SHA-256 Functions }
      *
      * @param {number} x
      *
      * @returns {number}
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      protected static gamma1_32(x: number): number
      {
        TS.Utils.checkIntNumberParameter("x", x, "TS.Security.Cryptography.gamma1_32");

        return TS.Security.Cryptography.correctNegative(this.rotateRight32(x, 17) ^ this.rotateRight32(x, 19) ^ this.shiftRight32(x, 10));
      }


      //TODO: Create the test functions.
      /**
      * @description Performs: (x & y) ^ (x & z) ^ (y & z)
      *
      * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.1.1 SHA-1 Functions }
      *
      * @param {number} x
      * @param {number} y
      * @param {number} z
      *
      * @returns {number}
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      protected static maj32(x: number, y: number, z: number): number
      {
        TS.Utils.checkIntNumberParameter("x", x, "TS.Security.Cryptography.maj32");
        TS.Utils.checkIntNumberParameter("y", y, "TS.Security.Cryptography.maj32");
        TS.Utils.checkIntNumberParameter("z", z, "TS.Security.Cryptography.maj32");

        return TS.Security.Cryptography.correctNegative((x & y) ^ (x & z) ^ (y & z));
      }


      //TODO: Create the test functions.  Add descripion
      /**
      * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.1.1 SHA-1 Functions }
      *
      * @param {TS.TypeCode.UInt64} x
      * @param {TS.TypeCode.UInt64} y
      * @param {TS.TypeCode.UInt64} z
      *
      * @returns {TS.TypeCode.UInt64}
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      protected static maj64(x: TS.TypeCode.UInt64, y: TS.TypeCode.UInt64, z: TS.TypeCode.UInt64): TS.TypeCode.UInt64
      {
        let tempMSInteger: number;
        let tempLSInteger: number;

        TS.Utils.checkUInt64NumberParameter("x", x, "TS.Security.Cryptography.maj64");
        TS.Utils.checkUInt64NumberParameter("y", y, "TS.Security.Cryptography.maj64");
        TS.Utils.checkUInt64NumberParameter("z", z, "TS.Security.Cryptography.maj64");

        tempMSInteger = this.maj32(x.mostSignificantInteger, y.mostSignificantInteger, z.mostSignificantInteger);
        tempLSInteger = this.maj32(x.leastSignificantInteger, y.leastSignificantInteger, z.leastSignificantInteger);

        return new TS.TypeCode.UInt64(tempMSInteger, tempLSInteger);
      }


      //TODO: Create the test functions.
      /**
      * @description Performs: (x ^ y ^ z)
      *
      * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.1.1 SHA-1 Functions }
      *
      * @param {number} x
      * @param {number} y
      * @param {number} z
      *
      * @returns {number}
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      protected static parity(x: number, y: number, z: number): number
      {
        TS.Utils.checkIntNumberParameter("x", x, "TS.Security.Cryptography.parity");
        TS.Utils.checkIntNumberParameter("y", y, "TS.Security.Cryptography.parity");
        TS.Utils.checkIntNumberParameter("z", z, "TS.Security.Cryptography.parity");

        return TS.Security.Cryptography.correctNegative((x ^ y ^ z));
      }


      /**
      * @description Rotates the bits in the unsigned 32 bit integer given in argument 'value' as many positions
      *  leftwise as given in argument 'positions'. Returns the value after rotation.
      *
      * @params {number} value, An unsigned 32 bit integer number.
      * @params {number} positions, Number of positions to rotate.
      *
      * @returns {number}, The resulting number after rotation.
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      protected static rotateLeft32(value: number, positions: number): number
      {
        if (!TS.Utils.Assert.isIntegerNumber(value) || value < 0)
        {
          debugger;
        }
        TS.Utils.checkUIntNumberParameter("value", value, "TS.Security.Cryptography.rotateLeft32");
        TS.Utils.checkUIntNumberParameter("positions", positions, "TS.Security.Cryptography.rotateLeft32");

        positions = positions % 32;
        return TS.Security.Cryptography.correctNegative((value << positions) | (value >>> (32 - positions)));
      }


      /**
      * @description Rotates the bits in the unsigned 32 bit integer given in argument 'value' as many positions
      *  rightwise as given in argument 'positions'. Returns the value after rotation.
      *
      * @params {number} value, An unsigned 32 bit integer number.
      * @params {number} positions, Number of positions to rotate.
      *
      * @returns {number}, The resulting number after rotation.
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      protected static rotateRight32(value: number, positions: number): number
      {
        TS.Utils.checkUIntNumberParameter("value", value, "TS.Security.Cryptography.rotateRight32");
        TS.Utils.checkUIntNumberParameter("positions", positions, "TS.Security.Cryptography.rotateRight32");

        positions = positions % 32;
        return TS.Security.Cryptography.correctNegative((value >>> positions) | (value << (32 - positions)));
      }


      /**
      * @description Rotates the bits in the 64 bit integer given in argument 'value' as many positions
      *  rightwise as given in argument 'positions'. Returns the value after rotation.
      *
      * @params {number} value, An unsigned 32 bit integer number.
      * @params {number} positions, Number of positions to rotate.
      *
      * @returns {number}, The resulting number after rotation.
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      protected static rotateRight64(value: TS.TypeCode.UInt64, positions: number): TS.TypeCode.UInt64
      {
        TS.Utils.checkUInt64NumberParameter("value", value, "TS.Security.Cryptography.rotateRight64");
        TS.Utils.checkUIntNumberParameter("positions", positions, "TS.Security.Cryptography.rotateRight32");

        positions = positions % 64;

        let tempMSInteger: number;
        let tempLSInteger: number;
        let returnUInt64: TS.TypeCode.UInt64;
        let swap: number;

        tempMSInteger = 0;
        tempLSInteger = 0;

        if (0 == positions)
        {
          tempMSInteger = value.mostSignificantInteger;
          tempLSInteger = value.leastSignificantInteger;
        }//END if

        if (0 < positions && positions < 32)
        {
          tempMSInteger = (value.mostSignificantInteger >>> positions) | (value.leastSignificantInteger << (32 - positions));
          tempLSInteger = (value.leastSignificantInteger >>> positions) | (value.mostSignificantInteger << (32 - positions));
        }//END if

        if (positions == 32)
        {
          tempMSInteger = value.leastSignificantInteger;
          tempLSInteger = value.mostSignificantInteger;
        }//END if

        if (32 < positions)
        {
          tempMSInteger = (value.leastSignificantInteger >>> (positions - 32)) | (value.mostSignificantInteger << (64 - positions));
          tempLSInteger = (value.mostSignificantInteger >>> (positions - 32)) | (value.leastSignificantInteger << (64 - positions));
        }//END else

        tempMSInteger = TS.Security.Cryptography.correctNegative(tempMSInteger);
        tempLSInteger = TS.Security.Cryptography.correctNegative(tempLSInteger);

        return new TS.TypeCode.UInt64(tempMSInteger, tempLSInteger);
      }


      /**
      * @description Shifts the bits in the unsigned 32 bit integer given in argument 'value' as many positions
      *  leftwise as given in argument 'positions'. Returns the value after shifting.
      *
      * @params {number} value, An unsigned 32 bit integer number.
      * @params {number} positions, Number of positions to shift.
      *
      * @returns {number}, the resulting number after shifting.
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      protected static shiftLeft32(value: number, positions: number): number
      {
        TS.Utils.checkUIntNumberParameter("value", value, "TS.Security.Cryptography.shiftRight32");
        TS.Utils.checkUIntNumberParameter("positions", positions, "TS.Security.Cryptography.rotateRight32");

        positions = positions % 32;
        value = value << positions;
        return TS.Security.Cryptography.correctNegative(value);
      }


      /**
      * @description Shifts the bits in the unsigned 32 bit integer given in argument 'value' as many positions
      *  rightwise as given in argument 'positions'. Returns the value after shifting.
      *
      * @params {number} value, An unsigned 32 bit integer number.
      * @params {number} positions, Number of positions to shift.
      *
      * @returns {number}, The resulting number after shifting.
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      protected static shiftRight32(value: number, positions: number): number
      {
        TS.Utils.checkUIntNumberParameter("value", value, "TS.Security.Cryptography.shiftRight32");
        TS.Utils.checkUIntNumberParameter("positions", positions, "TS.Security.Cryptography.rotateRight32");

        positions = positions % 32;
        value = value >>> positions;
        return TS.Security.Cryptography.correctNegative(value);
      }


      /**
      * @description Shifts the bits in the unsigned 64 bit integer given in argument 'value' as many positions
      *  rightwise as given in argument'positions'. Returns the value after shifting.
      *
      * @params {number} value, An unsigned 64 bit integer number.
      * @params {number} positions, Number of positions to shift.
      *
      * @returns {number}, The resulting number after shifting.
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      protected static shiftRight64(value: TS.TypeCode.UInt64, positions: number): TS.TypeCode.UInt64
      {
        TS.Utils.checkUInt64NumberParameter("value", value, "TS.Security.Cryptography.shiftRight64");
        TS.Utils.checkUIntNumberParameter("positions", positions, "TS.Security.Cryptography.shiftRight64");

        positions = positions % 64;
        let tempMSInteger: number;
        let tempLSInteger: number;
        let returnUInt64: TS.TypeCode.UInt64;
        let swap: number;

        tempMSInteger = 0;
        tempLSInteger = 0;

        if (0 == positions)
        {
          tempMSInteger = value.mostSignificantInteger;
          tempLSInteger = value.leastSignificantInteger;
        }//END if

        if (0 < positions && positions < 32)
        {
          tempMSInteger = value.mostSignificantInteger >>> positions;
          tempLSInteger = (value.leastSignificantInteger >>> positions) | (value.mostSignificantInteger << (32 - positions));
        }//END if

        if (positions == 32)
        {
          tempMSInteger = 0;
          tempLSInteger = value.mostSignificantInteger;
        }//END if

        if (32 < positions)
        {
          tempMSInteger = 0;
          tempLSInteger = value.mostSignificantInteger >>> (positions - 32);
        }//END if

        tempLSInteger = TS.Security.Cryptography.correctNegative(tempLSInteger);
        tempMSInteger = TS.Security.Cryptography.correctNegative(tempMSInteger);

        return new TS.TypeCode.UInt64(tempMSInteger, tempLSInteger);
      }


      //TODO: Create the test functions.
      /**
      * @description Performs: (ror 2) ^ (ror 13) ^ (ror 22)
      *
      * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.1.2 SHA-224 and SHA-256 Functions }
      *
      * @param {number} x
      *
      * @returns {number}
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      protected static sigma0_32(x: number): number
      {
        TS.Utils.checkIntNumberParameter("x", x, "TS.Security.Cryptography.sigma0_32");

        return TS.Security.Cryptography.correctNegative(this.rotateRight32(x, 2) ^ this.rotateRight32(x, 13) ^ this.rotateRight32(x, 22));
      }


      //TODO: Create the test functions.  Add descripion
      /**
      * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.1.3 SHA-384, SHA-512, SHA-512 / 224 and SHA-512 / 256 Functions }
      *
      * @param {TS.TypeCode.UInt64} x
      *
      * @returns {TS.TypeCode.UInt64}
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      protected static sigma0_64(x: TS.TypeCode.UInt64): TS.TypeCode.UInt64
      {
        let tempMSInteger: number;
        let tempLSInteger: number;
        let rot28: TS.TypeCode.UInt64;
        let rot34: TS.TypeCode.UInt64;
        let rot39: TS.TypeCode.UInt64;

        TS.Utils.checkUInt64NumberParameter("x", x, "TS.Security.Cryptography.sigma0_64");

        rot28 = this.rotateRight64(x, 28);
        rot34 = this.rotateRight64(x, 34);
        rot39 = this.rotateRight64(x, 39);

        tempMSInteger = rot28.mostSignificantInteger ^ rot34.mostSignificantInteger ^ rot39.mostSignificantInteger;
        tempLSInteger = rot28.leastSignificantInteger ^ rot34.leastSignificantInteger ^ rot39.leastSignificantInteger;

        tempLSInteger = TS.Security.Cryptography.correctNegative(tempLSInteger);
        tempMSInteger = TS.Security.Cryptography.correctNegative(tempMSInteger);

        return new TS.TypeCode.UInt64(tempMSInteger, tempLSInteger);
      }


      //TODO: Create the test functions.
      /**
      * @description Performs: (ror 6) ^ (ror 11) ^ (ror 25)
      *
      * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.1.2 SHA-224 and SHA-256 Functions }
      *
      * @param {number} x
      *
      * @returns {number}
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      protected static sigma1_32(x: number): number
      {
        TS.Utils.checkIntNumberParameter("x", x, "TS.Security.Cryptography.sigma1_32");

        return TS.Security.Cryptography.correctNegative(this.rotateRight32(x, 6) ^ this.rotateRight32(x, 11) ^ this.rotateRight32(x, 25));
      }

    }//END class

  }//END namespace
}//END namespace
