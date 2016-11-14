/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {

    /**
    * @description An enumeration which declares the two possible cipher operations. (ENCRYPT, DECRYPT).
    */
    export enum CipherOperationEnum
    {
      DECRYPT,
      ENCRYPT
    }


    /**
    * @description An enumeration which declares the possible stream states.
    */
    export enum StreamStateEnum
    {
      CREATED,
      INITIALIZED,
      REQUEST_FOR_CLOSE,
      CLOSED
    }

    export const MD5_KEY_SIZE = 64;
    export const MD5_HASH_SIZE = 16;

    export const SHA1_KEY_SIZE = 64;
    export const SHA1_HASH_SIZE = 20;

    export const SHA224_KEY_SIZE = 64;
    export const SHA224_HASH_SIZE = 28;

    export const SHA256_KEY_SIZE = 64;
    export const SHA256_HASH_SIZE = 32;

    export const SHA384_KEY_SIZE = 128;
    export const SHA384_HASH_SIZE = 48;

    export const SHA512_KEY_SIZE = 128;
    export const SHA512_HASH_SIZE = 64;

    export const HMAC_SHA256_KEY_SIZE = 64;
    export const HMAC_SHA256_HASH_SIZE = 32;

    export const HMAC_SHA384_KEY_SIZE = 128;
    export const HMAC_SHA384_HASH_SIZE = 48;

    export const HMAC_SHA512_KEY_SIZE = 128;
    export const HMAC_SHA512_HASH_SIZE = 64;


    //TODO: Crate the test functions.
    /**
    * @description Slices the data array given in argument 'data' in pieces of the length given in argument
    *  'sliceLengthInByte'. Each slice is an array of byte of the given length and represents one element of the return
    *  array. Thus the return array is a 2 dimensional byte array of the dimension 'n * sliceLengthInByte' where n is 
    *  the number of slices.
    *
    * @param {Array<number>} data, The data array to slice.
    * @param { number} sliceLengthInByte, The length of the slices. That value should match wiht the encryption block length.
    *  sliceLengthInByte has a default value of 4.
    *
    * @returns {Array<Array<number>}, The array of slices.
    *
    * @throws {TS.ArgumentOutOfRangeException}
    * @throws {TS.InvalidOperationException}
    * @throws {TS.ArgumentNullOrUndefinedException}
    * @throws {TS.InvalidTypeException}
    */
    export function sliceData(data: Array<number>, sliceLengthInByte: number = 4): Array<Array<number>>
    {
      let workingData: Array<number>;
      let resultArray: Array<Array<number>> = new Array<Array<number>>();

      TS.Utils.checkUByteArrayParameter("data", data, "TS.Security.sliceData");
      TS.Utils.checkUIntNumberParameter("sliceLengthInByte", sliceLengthInByte, "TS.Security.sliceData");

      if (sliceLengthInByte <= 0 || sliceLengthInByte > 255)
      {
        throw new TS.ArgumentOutOfRangeException("sliceLengthInByte", sliceLengthInByte, "Argument 'sliceLengthInByte' must be a value in range [1..255]. The error occured in function 'TS.Security.sliceData'.");
      }//END if

      if ((data.length % sliceLengthInByte) != 0)
      {
        throw new TS.InvalidOperationException("Slicing the data into blocks of length " + sliceLengthInByte.toString() + " failed because the data length is not a multitude of the required slice length. The error occured in function 'TS.Security.sliceData'.");
      }//END if

      workingData = data.slice();

      while (workingData.length > 0)
      {
        resultArray.push(workingData.slice(0, sliceLengthInByte));
        workingData = workingData.slice(sliceLengthInByte);
      }//END while

      return resultArray;
    }


    /**
    * @description Pads the byte array of given in argument data as required by the SHA(x) algorithm.
    *
    * @param {Array<number> | string} data
    * @returns {Array<number>}, An array of unsigned integers where each element represents four byte in the order
    *  [byte0][byte1][byte2][byte3].
    *
    * @throws {TS.ArgumentNullOrUndefinedException}
    * @throws {TS.InvalidTypeException}
    */
    export function pad_SHA(data: Array<number> | string): Array<number>
    {
      /**
      * @description The result array is an array of four byte words which is a simple unsigned integer in JavaScript.
      * @see fourByteWord
      */
      let resultArray: Array<number>;
      let messageArray: Array<number>;
      let messageLength: number;
      let UInt64MessageBitLength: TS.TypeCode.UInt64;

      /**
      * @description A four byte word in JavaScript is simply a number which holds four unsigned byte values in one
      *  unsigned integer value. The byte values are stored in order of appearance. That means the most significant
      *  byte is the first and the least significant byte is the last.
      *  [byte0][byte1][byte2][byte3] <=> UnsignedInteger
      */
      let fourByteWord: number;

      if (TS.Utils.Assert.isNullOrUndefined(data))
      {
        throw new TS.ArgumentNullOrUndefinedException("data", "Argument data must be null or undefined in function 'TS.Security.padMD5_SHA'.");
      }//END if


      if (!TS.Utils.Assert.isEmptyArray(data) && !TS.Utils.Assert.isString(data) && !TS.Utils.Assert.isUnsignedByteArray(data))
      {
        throw new TS.InvalidTypeException("data", data, "Argument data must be a valid string or an array of unsigned byte values in function 'TS.Security.padMD5_SHA'.");
      }//END if

      if (TS.Utils.Assert.isString(data))
      {
        if ((data as string).length > 0)
        {
          messageArray = TS.Encoding.UTF.UTF16StringToUTF8Array(data as string);
        }
        else
        {
          messageArray = new Array<number>();
        }
      }
      else
      {
        messageArray = (data as Array<number>).slice();
      }

      messageLength = messageArray.length;
      resultArray = new Array<number>();

      //
      // Slice the message in 4 character substrings and
      // and store the characters as bytes in a 32bit
      // integer. 
      //
      for (let index = 0; index < messageLength - 3; index += 4)
      {
        fourByteWord = messageArray[index] * 0x1000000 + messageArray[index + 1] * 0x10000 + messageArray[index + 2] * 0x100 + messageArray[index + 3];
        resultArray.push(fourByteWord);
      }//END for


      //
      // Add the remaining bytes, a stop bit and fill up with zeros up to a total length of 4 byte.
      // Add the four byte word to the result array afterwards.
      //
      switch (messageLength % 4)
      {
        case 0:
          {
            fourByteWord = TS.Security.UByteArrayToFourByteWord([0x80, 0x0, 0x0, 0x0]);
            break;
          }
        case 1:
          {
            fourByteWord = TS.Security.UByteArrayToFourByteWord([messageArray[messageLength - 1], 0x80, 0x0, 0x0]);
            break;
          }
        case 2:
          {
            fourByteWord = TS.Security.UByteArrayToFourByteWord([messageArray[messageLength - 2], messageArray[messageLength - 1], 0x80, 0x0]);
            break;
          }
        case 3:
          {
            fourByteWord = TS.Security.UByteArrayToFourByteWord([messageArray[messageLength - 3], messageArray[messageLength - 2], messageArray[messageLength - 1], 0x80]);
            break;
          }
      }//END switch

      resultArray.push(fourByteWord);

      //
      // Fill the result array with empty entries ( 0 values) until the  array has reached a length of: n * 512 + 448 
      //  in  bit. Each entry in the array has a length of 32 bit. 16 * 32 = 512, 14 * 32 = 448
      //
      while ((resultArray.length % 16) != 14)
      {
        resultArray.push(0);
      }//END while

      //
      // Calculate the message length in bit and store the result in a 64 bit unsigned integer. 64 bit = 8 byte.
      //
      UInt64MessageBitLength = TS.TypeCode.UInt64.UIntToUInt64(messageLength * 8);

      //
      // Add the message length in bit to the result array. The result array has length of n * 512 + 488 byte so far.
      // Adding the 8 byte of the UInt64 and the result array has a length of (n + 1) * 512.
      //
      resultArray.push(UInt64MessageBitLength.mostSignificantInteger, UInt64MessageBitLength.leastSignificantInteger);

      return resultArray;
    }


    /**
    * @description Pads the byte array  given in argument data as required by the MD5 algorithm.
    *
    * @param {Array<number> | string} data
    * @returns {Array<number>}, An array of unsigned integers where each element represents four byte in the order
    *  [byte0][byte1][byte2][byte3].
    *
    * @throws {TS.ArgumentNullOrUndefinedException}
    * @throws {TS.InvalidTypeException}
    */
    export function pad_MD5(data: Array<number> | string): Array<number>
    {
      let resultArray = TS.Security.pad_SHA(data);
      let temp1: number;
      let temp2: number;
      temp1 = TS.Utils.UInt32SwapSignificantByteOrder(resultArray.pop());
      temp2 = TS.Utils.UInt32SwapSignificantByteOrder(resultArray.pop());
      resultArray.push(temp1);
      resultArray.push(temp2);
      return resultArray;
    }


    /**
     * @description Takes an array of up to four unsigned byte values and returns them as four byte word, which is an
    *  unsigned integer in JavaScript. The bytes are arranged in the order of appearence. That means the first byte
    *  is stored at the most significant position and the last byte at the least significant position.
    *  [byte0][byte1][byte2][byte3] <=> UnsignedInteger
    *  That conversion is equivalent to:
    *
    *  byte0 * 0xFFFFFF + byte1 * 0xFFFF + byte2 * 0xFF + byte3
    * @param { Array<number>} byteArray, An array of up to 4 unsigned byte values.
    *
    * @returns {number}, The four byte word as unsigned integer.
    *
    * @throws {TS.ArgumentNullOrUndefinedException}
    * @throws {TS.InvalidTypeException}
    * @throws {TS.ArgumentOutOfRangeException}
    */
    export function UByteArrayToFourByteWord(byteArray: Array<number>): number
    {
      let result: number;
      let factor: number = 0x1000000;

      TS.Utils.checkUByteArrayParameter("byteArray", byteArray, "TS.Security.UByteArrayToFourByteWord")
      if (byteArray.length > 4)
      {
        throw new TS.ArgumentOutOfRangeException("byteArray", byteArray, "Argument 'byteArray' must be an array of unsigned bytes with a length < 4 in function 'TS.Security.UByteArrayToFourByteWord'.");
      }

      result = 0;

      for (let index = 0; index < byteArray.length; index++)
      {
        result += byteArray[index] * (factor >> (index * 8))
      }

      return result;
    }

    //TODO: Crate the test functions. Add descripion
    /**
    * @description An implementation of the padding algorithm as described in RFC2315. That algorithm is also known as
    *  PKCS7 padding.
    *
    * @param {Array<number>} data, The data array which gets padded.
    * @param {number} requiredBlockLength, The required length of the array. That value should match with the
    *  encryption block length. The default value is 16.
    * 
    * @returns {Array<number>}, The padded data array
    *
    * @throws {TS.ArgumentOutOfRangeException}
    * @throws {TS.ArgumentNullOrUndefinedException}
    * @throws {TS.InvalidTypeException}
    */
    export function padData(data: Array<number>, requiredBlockLength: number = 16): Array<number>
    {
      let resultArray: Array<number> = new Array<number>();
      let reminder: number;
      let index: number;
      let workingData: Array<number>;

      TS.Utils.checkUByteArrayParameter("data", data, "TS.Security.padData");
      TS.Utils.checkUIntNumberParameter("requiredBlockLength", requiredBlockLength, "TS.Security.padData");

      workingData = data.slice();
      reminder = workingData.length % requiredBlockLength;

      if (requiredBlockLength <= 0 || requiredBlockLength > 255)
      {
        throw new TS.ArgumentOutOfRangeException("requiredBlockLength", requiredBlockLength, "Argument 'requiredBlockLength' must be a value in range [1..255] in function TS.Security.padData.");
      }//END if

      if (reminder == 0)
      {
        for (index = requiredBlockLength; index > 0; index--)
        {
          workingData.push(requiredBlockLength);
        }//END if
      }
      else
      {
        for (index = requiredBlockLength - reminder; index > 0; index--)
        {
          workingData.push(requiredBlockLength - reminder);
        }//END if
      }

      return workingData;
    }


    //TODO: Crate the test functions. Add descripion
    /**
    * @description Removes the pad bytes from the data which were added by the padData function before.
    * 
    * @see TS.Security.padData
    * 
    * @param data, The data array which gets unpadded.
    * 
    * @returns {Array<number>}, The unpadded data array
    * 
    * @throws {TS.ArgumentException}
    * @throws {TS.ArgumentNullOrUndefinedException}
    * @throws {TS.InvalidTypeException}
    */
    export function unpadData(data: Array<number>): Array<number>
    {
      let resultArray: Array<number> = new Array<number>();
      let padLengthInByte: number;
      let index: number;
      let workingData: Array<number>;

      TS.Utils.checkUByteArrayParameter("data", data, "TS.Security.unpadData");

      workingData = data.slice();

      padLengthInByte = data[data.length - 1];

      if (((workingData.length - padLengthInByte) < 0) || (padLengthInByte > 255))
      {
        throw new TS.ArgumentException("data", data, "The 'data' given in function 'unpadData' appears to be not a padded byte array. The error occured in function TS.Security.unpadData.");
      }//END if

      resultArray = workingData.slice(0, workingData.length - padLengthInByte);

      return resultArray;
    }

    //TODO: Crate the test functions.
    /**
    * @description Execute the XOR function on corresponding elements of the input byte arrays and returns the result
    *  in a new byte array. Correspoding byte array elements are those which have a common index inside their array.
    *
    * @param {Array<number>} firstArray
    * @param {Array<number>} secondArray
    *
    * @returns {Array<number>}
    *
    * @throws {TS.ArgumentNullOrUndefinedException}
    * @throws {TS.InvalidTypeException}
    */
    export function XORByteArray(firstArray: Array<number>, secondArray: Array<number>): Array<number>
    {
      let resultArray: Array<number>;

      TS.Utils.checkUByteArrayParameter("firstArray", firstArray, "TS.Security.XORByteArray");
      TS.Utils.checkUByteArrayParameter("secondArray", secondArray, "TS.Security.XORByteArray");

      if (firstArray.length > secondArray.length)
      {
        return TS.Security.XORByteArray(secondArray, firstArray);
      }

      resultArray = new Array<number>();

      for (let index = 0; index < firstArray.length; index++)
      {
        resultArray.push(firstArray[index] ^ secondArray[index]);
      }

      for (let index = firstArray.length; index < secondArray.length; index++)
      {
        resultArray.push(secondArray[index]);
      }

      return resultArray;
    }


    /**
    * @description Returns an array of round constants as required for the SHA-224 and SHA-256 hash algorithm.
    *
    * @returns {Array<number>}
    */
    export function getSHA224_256RoundConstants(): Array<number>
    {
      return [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    }


    /**
    * @descriptions Returns a precalculated array of integer sine values from the values [1..64] multiplied by
    *  0x100000000.
    *
    * @see {@link https://www.ietf.org/rfc/rfc1321.txt | RFC 1321,3.4 Step 4. Process Message in 16‐Word Blocks}
    *
    * @returns {Array<number>}
    */
    export function getMD5_SineTable(): Array<number>
    {
      return [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391];
    }

    /**
    * @description Returns the substitution table as defined for the MD5 algorithm.
    *
    * @see {@link https://www.ietf.org/rfc/rfc1321.txt | IETF}
    *
    * @returns {Array<number>}
    */
    export function getMD5_PerRoundShiftAmountTable(): Array<number>
    {
      return [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
    }


    /**
    * @description Returns an array of precalculated modulo operation values over the set {0..255}.
    *
    * @returns {Array<number>}
    */
    export function getAES_multByTwoArray()
    {
      return [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94, 96, 98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154, 156, 158, 160, 162, 164, 166, 168, 170, 172, 174, 176, 178, 180, 182, 184, 186, 188, 190, 192, 194, 196, 198, 200, 202, 204, 206, 208, 210, 212, 214, 216, 218, 220, 222, 224, 226, 228, 230, 232, 234, 236, 238, 240, 242, 244, 246, 248, 250, 252, 254, 27, 25, 31, 29, 19, 17, 23, 21, 11, 9, 15, 13, 3, 1, 7, 5, 59, 57, 63, 61, 51, 49, 55, 53, 43, 41, 47, 45, 35, 33, 39, 37, 91, 89, 95, 93, 83, 81, 87, 85, 75, 73, 79, 77, 67, 65, 71, 69, 123, 121, 127, 125, 115, 113, 119, 117, 107, 105, 111, 109, 99, 97, 103, 101, 155, 153, 159, 157, 147, 145, 151, 149, 139, 137, 143, 141, 131, 129, 135, 133, 187, 185, 191, 189, 179, 177, 183, 181, 171, 169, 175, 173, 163, 161, 167, 165, 219, 217, 223, 221, 211, 209, 215, 213, 203, 201, 207, 205, 195, 193, 199, 197, 251, 249, 255, 253, 243, 241, 247, 245, 235, 233, 239, 237, 227, 225, 231, 229];
    }

    /**
    * @description Returns an array of precalculated modulo operation values over the set {0..255}.
    *
    * @returns {Array<number>}
    */
    export function getAES_multByThreeArray()
    {
      return [0, 3, 6, 5, 12, 15, 10, 9, 24, 27, 30, 29, 20, 23, 18, 17, 48, 51, 54, 53, 60, 63, 58, 57, 40, 43, 46, 45, 36, 39, 34, 33, 96, 99, 102, 101, 108, 111, 106, 105, 120, 123, 126, 125, 116, 119, 114, 113, 80, 83, 86, 85, 92, 95, 90, 89, 72, 75, 78, 77, 68, 71, 66, 65, 192, 195, 198, 197, 204, 207, 202, 201, 216, 219, 222, 221, 212, 215, 210, 209, 240, 243, 246, 245, 252, 255, 250, 249, 232, 235, 238, 237, 228, 231, 226, 225, 160, 163, 166, 165, 172, 175, 170, 169, 184, 187, 190, 189, 180, 183, 178, 177, 144, 147, 150, 149, 156, 159, 154, 153, 136, 139, 142, 141, 132, 135, 130, 129, 155, 152, 157, 158, 151, 148, 145, 146, 131, 128, 133, 134, 143, 140, 137, 138, 171, 168, 173, 174, 167, 164, 161, 162, 179, 176, 181, 182, 191, 188, 185, 186, 251, 248, 253, 254, 247, 244, 241, 242, 227, 224, 229, 230, 239, 236, 233, 234, 203, 200, 205, 206, 199, 196, 193, 194, 211, 208, 213, 214, 223, 220, 217, 218, 91, 88, 93, 94, 87, 84, 81, 82, 67, 64, 69, 70, 79, 76, 73, 74, 107, 104, 109, 110, 103, 100, 97, 98, 115, 112, 117, 118, 127, 124, 121, 122, 59, 56, 61, 62, 55, 52, 49, 50, 35, 32, 37, 38, 47, 44, 41, 42, 11, 8, 13, 14, 7, 4, 1, 2, 19, 16, 21, 22, 31, 28, 25, 26];
    }

    /**
    * @description Returns an array of precalculated modulo operation values over the set {0..255}.
    *
    * @returns {Array<number>}
    */
    export function getAES_multByFourteenArray()
    {
      return [0, 14, 28, 18, 56, 54, 36, 42, 112, 126, 108, 98, 72, 70, 84, 90, 224, 238, 252, 242, 216, 214, 196, 202, 144, 158, 140, 130, 168, 166, 180, 186, 219, 213, 199, 201, 227, 237, 255, 241, 171, 165, 183, 185, 147, 157, 143, 129, 59, 53, 39, 41, 3, 13, 31, 17, 75, 69, 87, 89, 115, 125, 111, 97, 173, 163, 177, 191, 149, 155, 137, 135, 221, 211, 193, 207, 229, 235, 249, 247, 77, 67, 81, 95, 117, 123, 105, 103, 61, 51, 33, 47, 5, 11, 25, 23, 118, 120, 106, 100, 78, 64, 82, 92, 6, 8, 26, 20, 62, 48, 34, 44, 150, 152, 138, 132, 174, 160, 178, 188, 230, 232, 250, 244, 222, 208, 194, 204, 65, 79, 93, 83, 121, 119, 101, 107, 49, 63, 45, 35, 9, 7, 21, 27, 161, 175, 189, 179, 153, 151, 133, 139, 209, 223, 205, 195, 233, 231, 245, 251, 154, 148, 134, 136, 162, 172, 190, 176, 234, 228, 246, 248, 210, 220, 206, 192, 122, 116, 102, 104, 66, 76, 94, 80, 10, 4, 22, 24, 50, 60, 46, 32, 236, 226, 240, 254, 212, 218, 200, 198, 156, 146, 128, 142, 164, 170, 184, 182, 12, 2, 16, 30, 52, 58, 40, 38, 124, 114, 96, 110, 68, 74, 88, 86, 55, 57, 43, 37, 15, 1, 19, 29, 71, 73, 91, 85, 127, 113, 99, 109, 215, 217, 203, 197, 239, 225, 243, 253, 167, 169, 187, 181, 159, 145, 131, 141];
    }

    /**
    * @description Returns an array of precalculated modulo operation values over the set {0..255}.
    *
    * @returns {Array<number>}
    */
    export function getAES_multByThirteenArray()
    {
      return [0, 13, 26, 23, 52, 57, 46, 35, 104, 101, 114, 127, 92, 81, 70, 75, 208, 221, 202, 199, 228, 233, 254, 243, 184, 181, 162, 175, 140, 129, 150, 155, 187, 182, 161, 172, 143, 130, 149, 152, 211, 222, 201, 196, 231, 234, 253, 240, 107, 102, 113, 124, 95, 82, 69, 72, 3, 14, 25, 20, 55, 58, 45, 32, 109, 96, 119, 122, 89, 84, 67, 78, 5, 8, 31, 18, 49, 60, 43, 38, 189, 176, 167, 170, 137, 132, 147, 158, 213, 216, 207, 194, 225, 236, 251, 246, 214, 219, 204, 193, 226, 239, 248, 245, 190, 179, 164, 169, 138, 135, 144, 157, 6, 11, 28, 17, 50, 63, 40, 37, 110, 99, 116, 121, 90, 87, 64, 77, 218, 215, 192, 205, 238, 227, 244, 249, 178, 191, 168, 165, 134, 139, 156, 145, 10, 7, 16, 29, 62, 51, 36, 41, 98, 111, 120, 117, 86, 91, 76, 65, 97, 108, 123, 118, 85, 88, 79, 66, 9, 4, 19, 30, 61, 48, 39, 42, 177, 188, 171, 166, 133, 136, 159, 146, 217, 212, 195, 206, 237, 224, 247, 250, 183, 186, 173, 160, 131, 142, 153, 148, 223, 210, 197, 200, 235, 230, 241, 252, 103, 106, 125, 112, 83, 94, 73, 68, 15, 2, 21, 24, 59, 54, 33, 44, 12, 1, 22, 27, 56, 53, 34, 47, 100, 105, 126, 115, 80, 93, 74, 71, 220, 209, 198, 203, 232, 229, 242, 255, 180, 185, 174, 163, 128, 141, 154, 151];
    }

    /**
    * @description Returns an array of precalculated modulo operation values over the set {0..255}.
    *
    * @returns {Array<number>}
    */
    export function getAES_multByElevenArray()
    {
      return [0, 11, 22, 29, 44, 39, 58, 49, 88, 83, 78, 69, 116, 127, 98, 105, 176, 187, 166, 173, 156, 151, 138, 129, 232, 227, 254, 245, 196, 207, 210, 217, 123, 112, 109, 102, 87, 92, 65, 74, 35, 40, 53, 62, 15, 4, 25, 18, 203, 192, 221, 214, 231, 236, 241, 250, 147, 152, 133, 142, 191, 180, 169, 162, 246, 253, 224, 235, 218, 209, 204, 199, 174, 165, 184, 179, 130, 137, 148, 159, 70, 77, 80, 91, 106, 97, 124, 119, 30, 21, 8, 3, 50, 57, 36, 47, 141, 134, 155, 144, 161, 170, 183, 188, 213, 222, 195, 200, 249, 242, 239, 228, 61, 54, 43, 32, 17, 26, 7, 12, 101, 110, 115, 120, 73, 66, 95, 84, 247, 252, 225, 234, 219, 208, 205, 198, 175, 164, 185, 178, 131, 136, 149, 158, 71, 76, 81, 90, 107, 96, 125, 118, 31, 20, 9, 2, 51, 56, 37, 46, 140, 135, 154, 145, 160, 171, 182, 189, 212, 223, 194, 201, 248, 243, 238, 229, 60, 55, 42, 33, 16, 27, 6, 13, 100, 111, 114, 121, 72, 67, 94, 85, 1, 10, 23, 28, 45, 38, 59, 48, 89, 82, 79, 68, 117, 126, 99, 104, 177, 186, 167, 172, 157, 150, 139, 128, 233, 226, 255, 244, 197, 206, 211, 216, 122, 113, 108, 103, 86, 93, 64, 75, 34, 41, 52, 63, 14, 5, 24, 19, 202, 193, 220, 215, 230, 237, 240, 251, 146, 153, 132, 143, 190, 181, 168, 163];
    }

    /**
    * @description Returns an array of precalculated modulo operation values over the set {0..255}.
    *
    * @returns {Array<number>}
    */
    export function getAES_multByNineArray()
    {
      return [0, 9, 18, 27, 36, 45, 54, 63, 72, 65, 90, 83, 108, 101, 126, 119, 144, 153, 130, 139, 180, 189, 166, 175, 216, 209, 202, 195, 252, 245, 238, 231, 59, 50, 41, 32, 31, 22, 13, 4, 115, 122, 97, 104, 87, 94, 69, 76, 171, 162, 185, 176, 143, 134, 157, 148, 227, 234, 241, 248, 199, 206, 213, 220, 118, 127, 100, 109, 82, 91, 64, 73, 62, 55, 44, 37, 26, 19, 8, 1, 230, 239, 244, 253, 194, 203, 208, 217, 174, 167, 188, 181, 138, 131, 152, 145, 77, 68, 95, 86, 105, 96, 123, 114, 5, 12, 23, 30, 33, 40, 51, 58, 221, 212, 207, 198, 249, 240, 235, 226, 149, 156, 135, 142, 177, 184, 163, 170, 236, 229, 254, 247, 200, 193, 218, 211, 164, 173, 182, 191, 128, 137, 146, 155, 124, 117, 110, 103, 88, 81, 74, 67, 52, 61, 38, 47, 16, 25, 2, 11, 215, 222, 197, 204, 243, 250, 225, 232, 159, 150, 141, 132, 187, 178, 169, 160, 71, 78, 85, 92, 99, 106, 113, 120, 15, 6, 29, 20, 43, 34, 57, 48, 154, 147, 136, 129, 190, 183, 172, 165, 210, 219, 192, 201, 246, 255, 228, 237, 10, 3, 24, 17, 46, 39, 60, 53, 66, 75, 80, 89, 102, 111, 116, 125, 161, 168, 179, 186, 133, 140, 151, 158, 233, 224, 251, 242, 205, 196, 223, 214, 49, 56, 35, 42, 21, 28, 7, 14, 121, 112, 107, 98, 93, 84, 79, 70];
    }

    /**
    * @description Returns an array of substitution values as defined in the AES algorithm.
    *
    * @returns {Array<number>}
    */
    export function getAES_substitutionTable()
    {
      return [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22];
    }

    /**
    * @description Returns an array of inverse substitution values as defined in the AES algorithm.
    *
    * @returns {Array<number>}
    */
    export function getAES_inverseSubstitutionTable()
    {
      return [82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37, 114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146, 108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132, 144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6, 208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107, 58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115, 150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110, 71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27, 252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244, 31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125];
    }

    /**
    * @description Returns an array of round constant values as defined in the AES algorithm.
    *
    * @returns {Array<number>}
    */
    export function getAES_roundConstants()
    {
      return [141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141];
    }

  }//END namespace
}//END namespace
