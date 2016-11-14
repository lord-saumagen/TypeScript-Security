/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {

    function getRoundConstant(index: number): number
    {
      return TS.Security.getAES_roundConstants()[index];
    }


    function getSubstitution(index: number): number
    {
      return TS.Security.getAES_substitutionTable()[index];
    }


    /**
    * @class TS.Security.AES
    *
    * @description This class is an implements of the ADVANCED ENCRYPTION STANDARD (AES) as described in the FIPS
    *  publication fips-197, 'Announcing the ADVANCED ENCRYPTION STANDARD (AES)'. The cipher mode decribed in that
    *  publication is also identical to the ELECTRONIC CODE BOOK (ECB) operation mode described in the NIST
    *  publication 800-38a, 'Recommendation for Block Cipher Modes of Operation'.
    * 
    * @see {@link http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf | NIST}
    * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
    */
    export class AES extends TS.Security.Cryptography
    {

      /** 
      * @description The working key byte array holds the working key which was created from the initial key by the key
      *  expansion function.
      * 
      * @see {TS.Security.AES.expandKey}
      *
      * @protected
      */
      protected workingKeyByteArray: Array<number>;

      /**
      * @description Number of rounds executed per cipher operation. The value of this variable depends on the key 
      *  lenght used in the constructor.
      * 
      * @protected
      */
      protected rounds: number;

      /**
      * @constructor
      *
      * @description Create a new AES instance with the key given in argument 'keyByteArray'. The 'keyByteArray' must
      *  have a total length of 128, 192 or 256 bits. That means the 'keyByteArray' array must have a length of either
      *  16, 24 or 32. Using a key which doesn't comply with that rule will raise an exception.
      *
      * @param {Array<number>} keyByteArray, An array of [16 | 24 | 32] byte holding the key.
      *
      * @throws {TS.ArgumentNullOrUndefinedException#}
      * @throws {TS.InvalidTypeException}
      * @throws {TS.ArgumentOutOfRangeException}
      */
      constructor(keyByteArray: Array<number>)
      {
        TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.AES.constructor");
        
        super();

        switch (keyByteArray.length)
        {
          case 16:
            {
              this.rounds = 10;
              this.workingKeyByteArray = TS.Security.AES.expandKey(keyByteArray);
              break;
            }
          case 24:
            {
              this.rounds = 12;
              this.workingKeyByteArray = TS.Security.AES.expandKey(keyByteArray);
              break;
            }
          case 32:
            {
              this.rounds = 14;
              this.workingKeyByteArray = TS.Security.AES.expandKey(keyByteArray);
              break;
            }
          default:
            {
              this.rounds = 0;
              this.workingKeyByteArray = new Array<number>();
              throw new TS.ArgumentOutOfRangeException("keyByteArray", keyByteArray, "The argument 'keyByteArray' must be a byte array with one of the following lengths: [16,24,32]. All other array lengths are considered invalid.");
            }
        }//END switch
      }


      /**
      * @description Encrypts the data provided in argument 'data' and returns the enrypted data as byte array. The
      *  data must be aligned to 16 byte. That means the total length of the data byte array must be n * 16, where n is
      *  any positive integer number greater zero.
      *
      * @param {Array<number>} data, The plain data array.
      *
      * @returns {Array<number>}, The enrcypted data array.
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      * @throws {TS.ArgumentException}
      */
      public encrypt(data: Array<number>): Array<number>
      {
        let resultByteArray: Array<number>;
        let dataByteArray: Array<number>;

        TS.Utils.checkUByteArrayParameter("data", data,"TS.Security.AES.encrypt");

        if ((data.length % 16) != 0)
        {
          throw new TS.ArgumentException("data", data, "The 'data' must be an array of n * 16 byte elements (the AES block size). Use the 'padData' function in order to give your data an appropriate length.");
        }//END if

        dataByteArray = data.slice();
        resultByteArray = new Array<number>();

        while (dataByteArray.length > 0)
        {
          resultByteArray = resultByteArray.concat(this.encryptDecryptInternal(dataByteArray.slice(0, 16), TS.Security.CipherOperationEnum.ENCRYPT))
          dataByteArray = dataByteArray.slice(16);
        }//END while

        return resultByteArray;
      }


      /**
      * @description Decrypts a block of 16 byte cipher data and returns the decrypted block as byte array.
      *
      * @param {Array<number>} dataByteArray, The array must be aligned to 16 byte. That means the length must be
      *  n * 16, where n is any positive integer number greater zero.
      *
      * @returns {Array<number>}, The decrypted data as byte array.
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      * @throws {TS.ArgumentException}
      */
      public decrypt(dataByteArray: Array<number>): Array<number>
      {
        let resultByteArray: Array<number>;
        let dataArray: Array<number>;

        TS.Utils.checkUByteArrayParameter("dataByteArray", dataByteArray, "TS.Security.AES.decrypt");

        if ((dataByteArray.length % 16) != 0)
        {
          throw new TS.ArgumentException("dataByteArray", dataByteArray, "The 'dataByteArray' must be an array of n * 16 elements (the AES block size).");
        }//END if

        dataArray = dataByteArray.slice();
        resultByteArray = new Array<number>();

        while (dataArray.length > 0)
        {
          resultByteArray = resultByteArray.concat(this.encryptDecryptInternal(dataArray.slice(0, 16), TS.Security.CipherOperationEnum.DECRYPT))
          dataArray = dataArray.slice(16);
        }//END while

        return resultByteArray;
      }


      /**
      * @description Encrypts or decrypts the data given in argument 'dataByteArray' and returns the processed data as
      *  byte array.
      *
      * @protected
      *
      * @param {Array<number>} dataByteArray, array of 16 byte values.
      * @param {CipherOperationEnum} cipherOperation
      * 
      * @return {Array<number>}, The resulting encrypted or decrypted data as byte array.
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      * @throws {TS.ArgumentException}
      */
      protected encryptDecryptInternal(dataByteArray: Array<number>, cipherOperation: CipherOperationEnum): Array<number>
      {
        let state: State;
        let index: number;
        let resultByteArray: Array<number>;

        TS.Utils.checkUByteArrayParameter("dataByteArray", dataByteArray, "TS.Security.AES.encryptDecryptInternal");
        TS.Utils.checkParameter("cipherOperation", cipherOperation, "TS.Security.AES.encryptDecryptInternal");

        if (!TS.Utils.Assert.isValueOfEnum(cipherOperation, TS.Security.CipherOperationEnum))
        {
          throw new TS.InvalidTypeException("cipherOperation", cipherOperation, "Argument 'cipherOperation' must be a valid element of the 'TS.Security.AES.encryptDecryptInternal' enumeration in function 'TS.Security.AES_CFB_Stream.constructor'.");
        }//END if

        resultByteArray = new Array<number>();
        index = 0;
        state = new State(dataByteArray);

        if (cipherOperation == CipherOperationEnum.ENCRYPT)
        {
          state.encrypt(this.workingKeyByteArray, this.rounds);
        }//END if
        else
        {
          state.decrypt(this.workingKeyByteArray, this.rounds);
        }//END else

        return state.toArray();
      }


      /**
      * @description The function substitues each byte in the byteArray by its substitute and returns the new created
      *  byte array.
      *
      * @private
      * @static
      *
      * @returns {Array<number>}
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      private static substituteBytes(byteArray: Array<number>): Array<number>
      {
        var index: number;
        var resultByteArray: Array<number>;

        TS.Utils.checkUByteArrayParameter("byteArray", byteArray, "TS.Security.AES.substituteBytes");

        resultByteArray = new Array<number>();

        for (index = 0; index < byteArray.length; index++)
        {
          resultByteArray[index] = getSubstitution(byteArray[index]);
        }//END for

        return resultByteArray;
      }


      /**
      * @description Expands the initial key and returns the resulting working key as byte array.
      * 
      * @private
      * @static
      *
      * @see {TS.Security.AES.workingKeyByteArray}
      * @see {@link http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf} Chapter 5.2 Key Expansion
      * 
      * @param {Array<number>} keyByteArray, An array of bytes which holds the initial key.
      * @param {number} rounds
      * 
      * @returns {Array<number>}, The resulting working key as byte array.
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      * @throws {TS.ArgumentOutOfRangeException}
      */
      private static expandKey(keyByteArray: Array<number>): Array<number>
      {
        let tempArray: Array<Array<number>>;
        let tempWord: Array<number>;
        let resultArray: Array<number>
        let index: number;
        let columnIndex: number;
        let roundConstantArray: Array<number>;
        let blockSizeInWords = 4;
        let keyLengthInWords: number;
        let rounds: number;

        TS.Utils.checkUByteArrayParameter("byteArray", keyByteArray, "TS.Security.AES.expandKey");

        tempArray = new Array<Array<number>>();
        resultArray = new Array<number>();
        index = 0;

        switch (keyByteArray.length)
        {
          case 16:
            {
              rounds = 10;
              break;
            }
          case 24:
            {
              rounds = 12;
              break;
            }
          case 32:
            {
              rounds = 14;
              break;
            }
          default:
            {
              rounds = 0;
              throw new TS.ArgumentOutOfRangeException("keyByteArray", keyByteArray, "The argument 'keyByteArray' must be a byte array with one of the following lengths: [16,24,32]. All other array lengths are considered invalid.");
            }
        }//END switch

        keyLengthInWords = keyByteArray.length / 4;

        while (index * 4 < keyByteArray.length)
        {
          tempArray[index] = keyByteArray.slice(index * 4, (index + 1) * 4);
          index++;
        }

        for (index = keyLengthInWords; index < blockSizeInWords * (rounds + 1); index++)
        {
          tempWord = tempArray[index - 1];

          if (index % keyLengthInWords === 0)
          {
            roundConstantArray = [getRoundConstant(index / keyLengthInWords), 0, 0, 0];
            tempWord = this.rotateLeft(tempWord, 1);
            tempWord = this.substituteBytes(tempWord);
            tempWord = this.xorWord(tempWord, roundConstantArray);
          }//END if
          else if (keyLengthInWords > 6 && index % keyLengthInWords === 4)
          {
            tempWord = TS.Security.AES.substituteBytes(tempWord);
          }//END else
          tempArray[index] = this.xorWord(tempArray[index - keyLengthInWords], tempWord);
        }//END for

        for (index = 0; index < tempArray.length; index++)
        {
          for (columnIndex = 0; columnIndex < 4; columnIndex++)
          {
            resultArray.push(tempArray[index][columnIndex]);
          }//END for
        }//END for

        return resultArray;
      }

    }//END class

  }//END namespace
}//END namespace