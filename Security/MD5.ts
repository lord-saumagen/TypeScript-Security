/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {
    /**
    * @class TS.Security.MD5
    *
    * @classdesc This class implements the MD5 hash algorithm as described in the IETF publication
    *  'The MD5 Message-Digest Algorithm'.
    *
    * @see {@link https://www.ietf.org/rfc/rfc1321.txt | IETF }
    */
    export class MD5 extends Cryptography
    {

      /**
      * 
      * @param {string | Array<number>} message, Either a simple text string or an array of unsigned byte values.
      *
      * @returns {string}, The resulting digest / MD5 as HEX string.
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      public static encrypt(message: string | Array<number>): string
      {
        let wordArray: Array<number>;

        //
        // Declare word array variables
        //
        let H0: number;
        let H1: number;
        let H2: number;
        let H3: number;

        //
        // Declare the sine values table
        //
        let sineTable: Array<number>;

        let perRoundShiftAmountTable: Array<number>;

        //
        // RFC 1321
        //
        //  3.1 Step 1. Append Padding Bits
        //  3.2 Step 2. Append Length
        //

        //
        // Pad the message
        //
        wordArray = TS.Security.pad_MD5(message);


        //
        // RFC 1321,3.3 Step 3. Initialize MD Buffer
        //
        //3.3 Step 3. Initialize MD Buffer
        //  A four‐word buffer (A, B, C, D) is used to compute the message digest.Here each of A,  B,  C,  D is a 32‐bit register. 
        //  These registers are     initialized to the following values in hexadecimal, low‐order bytes     first): 
        //
        // word A: 01 23 45 67
        // word B: 89 ab cd ef
        // word C: fe dc ba 98
        // word D: 76 54 32 10
        //

        H0 = TS.Security.UByteArrayToFourByteWord([0x67, 0x45, 0x23, 0x01]);
        H1 = TS.Security.UByteArrayToFourByteWord([0xef, 0xcd, 0xab, 0x89]);
        H2 = TS.Security.UByteArrayToFourByteWord([0x98, 0xba, 0xdc, 0xfe]);
        H3 = TS.Security.UByteArrayToFourByteWord([0x10, 0x32, 0x54, 0x76]);


        //
        // RFC 1321,3.4 Step 4. Process Message in 16‐Word Blocks
        //

        //
        // Precalculated integer sine values of the values [1..64] * 0x100000000
        //
        sineTable = TS.Security.getMD5_SineTable();

        //
        // Predefined per round shift amount table
        //
        perRoundShiftAmountTable = TS.Security.getMD5_PerRoundShiftAmountTable();

        for (let outerIndex = 0; outerIndex < wordArray.length; outerIndex += 16)
        {
          //
          // Define the round variables.
          //
          let roundA: number;
          let roundB: number;
          let roundC: number;
          let roundD: number;
          let funcResult: number;
          let chunkIndex: number;

          //
          // Create one chunk of 16 words for each round.
          //
          let chunk: Array<number>;
          chunk = new Array<number>();

          for (let innerIndex = 0; innerIndex < 16; innerIndex++)
          {
            chunk.push(TS.Utils.UInt32SwapSignificantByteOrder(wordArray[outerIndex + innerIndex]));
          }

          //
          // Initialize the round variable with the last values of the hash variables.
          //
          roundA = H0;
          roundB = H1;
          roundC = H2;
          roundD = H3;

          for (let roundIndex = 0; roundIndex < 64; roundIndex++)
          {
            if (roundIndex < 16)
            {
              funcResult = TS.Security.Cryptography.MD5FuncOne(roundB, roundC, roundD);
              chunkIndex = roundIndex;
            }

            if ((roundIndex > 15) && (roundIndex < 32 ))
            {
              funcResult = TS.Security.Cryptography.MD5FuncTwo(roundB, roundC, roundD);
              chunkIndex = (5 * roundIndex + 1) % 16
            }

            if ((roundIndex > 31) && (roundIndex < 48))
            {
              funcResult = TS.Security.Cryptography.MD5FuncThree(roundB, roundC, roundD);
              chunkIndex = (3 * roundIndex + 5) % 16
            }

            if ((roundIndex > 47) && (roundIndex < 64))
            {
              funcResult = TS.Security.Cryptography.MD5FuncFour(roundB, roundC, roundD);
              chunkIndex = (7 * roundIndex) % 16
            }

            let dTemp = roundD;
            roundD = roundC;
            roundC = roundB;
            roundB = (roundB + TS.Security.Cryptography.rotateLeft32((roundA + funcResult + sineTable[roundIndex] + chunk[chunkIndex]) % 0x100000000, perRoundShiftAmountTable[roundIndex])) % 0x100000000; 
            roundA = dTemp;
          }//END for

          H0 = (H0 + roundA) % 0x100000000;
          H1 = (H1 + roundB) % 0x100000000;
          H2 = (H2 + roundC) % 0x100000000;
          H3 = (H3 + roundD) % 0x100000000;

        }//END for

        //
        // Create a hex string and return this string as result.
        //
        return TS.Utils.UInt32ToHexString(TS.Utils.UInt32SwapSignificantByteOrder(H0)) + TS.Utils.UInt32ToHexString(TS.Utils.UInt32SwapSignificantByteOrder(H1)) + TS.Utils.UInt32ToHexString(TS.Utils.UInt32SwapSignificantByteOrder(H2)) + TS.Utils.UInt32ToHexString(TS.Utils.UInt32SwapSignificantByteOrder(H3));
      }


    }//END class


  }//END namespace
}//END namespace 