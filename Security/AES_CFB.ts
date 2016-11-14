/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {

    /**
    * @class TS.Security.AES_CFB
    *
    * @description This is an implementation of the CIPHER FEEDBACK (CFB) operation mode as described in the NIST
    *  publication 800-38a, 'Recommendation for Block Cipher Modes of Operation'.
    *
    * @extends {TS.Scecurity.AES}
    *
    * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
    */
    export class AES_CFB extends TS.Security.AES
    {
      /** 
       * @private 
       */
      private inputState: State;

      /*
       * @private
       */
      private IV: State;

      /** 
       * @private
       */
      private segmentSizeInBit: number;


      /**
      * @constructor
      *
      * @description Creates a new AES_CFB instance with the key given in argument 'keyByteArray', the initialisation
      *  vector given in argument 'initialisationVector' and the segment size in bit given in argument
      *  'segmentSizeInBit'. The 'keyByteArray' must have a total length of 128, 192 or 256 bits. That means the
      *  'keyByteArray' array must have a length of either 16, 24 or 32. Using a key which doesn't comply with that
      *  rule will raise an exception. The initialisation vector must be an array of unsigned byte values with a total
      *  of 16 elements. The 'segmentSizeInBit' must be a value in the range of [1..128]. The segment size denotes the
      *  data size the cipher object will operate on. The AES_CFB mode is the only AES operation mode which give you
      *  totally freedom in choosing the data size you intend to use. At least in the allowed range between 1 and 128.
      *  So if you have to encrypt / decrypt single bits, this operation mode will be your best choice But you have to
      *  pay for that freedom with a bad runtime behavior. It goes from worst behavior by a segment size of 1 bit, to
      *  best behavior by a segment size of 128 bit, which is the normal block length of the AES algorithm.
      * 
      * @param {Array<number>} keyByteArray, An array of [16 | 24 | 32] byte holding the key.
      * @param {Array<number>} initialisationVector, An array of 16 byte holding the initalisation vector.
      * @param {number} segmentSizeInBit, Must be a numbe between [1..128].
      * 
      * @throws {TS.ArgumentOutOfRangeException}
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      constructor(keyByteArray: Array<number>, initialisationVector: Array<number>, segmentSizeInBit: number)
      {
        TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.AES_CFB.constructor");
        TS.Utils.checkUByteArrayParameter("initialisationVector", initialisationVector, "TS.Security.AES_CFB.constructor");
        TS.Utils.checkUIntNumberParameter("segmentSizeInBit", segmentSizeInBit, "TS.Security.AES_CFB.constructor");

        if (initialisationVector.length != 16)
        {
          throw new TS.ArgumentOutOfRangeException("initialisationVector", initialisationVector, "Argument 'initialisationVector' must be a byte array of the length 16 in function 'TS.Security.AES_CFB.constructor'.");
        }//END if

        if ((segmentSizeInBit < 1) || (segmentSizeInBit > 128))
        {
          throw new TS.ArgumentOutOfRangeException("segmentSizeInBit", segmentSizeInBit, "The argument value must be a value in the range of [1..128]. Error occured in 'TS.Security.AES_CFB.constructor'.");
        }//END if

        super(keyByteArray);

        this.segmentSizeInBit = segmentSizeInBit;
        this.IV = new State(initialisationVector);
      }


      /**
      * @description Encrypts the data given in argument 'plainDataByteArray' and returns the encrypted data as byte
      *  array. This function will not work if the segment size doesn't align with byte length (8 bit). 
      * 
      * @override
      *
      * @param {Array<number>} plainDataByteArray
      *
      * @returns {Array<number>} The encrypted data as byte array.
      *
      * @throws {TS.InvalidOperationException}
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      public encrypt(plainDataByteArray : Array<number>): Array<number>
      {
        TS.Utils.checkUByteArrayParameter("plainDataByteArray", plainDataByteArray, "TS.Security.AES_CFB.encrypt");

        if ((this.segmentSizeInBit % 8) != 0)
        {
          throw new TS.InvalidOperationException("The 'encrypt' function which uses a byte array as input parameter can only be use if the segment size aligns with 8 bit. That means, segment size must be a value which is n * 8, where n is a positive integer > 0. Use the 'encryptBitString' function if the segment size doesn't fit. Error occured in 'TS.Security.AES_CFB.encrypt'.");
        }//END if

        return this.encryptDecryptInternal(plainDataByteArray, CipherOperationEnum.ENCRYPT);
      }


      /**
      * @description Decrypts the data given in argument 'plainDataByteArray' and returns the decrypted data as byte
      *  array. This function will not work if the segment size doesn't align with byte length (8 bit). 
      *
      * @override
      *
      * @param {Array<number>} cipherDataByteArray
      * 
      * @returns {Array<number>} The decrypted data as byte array.
      *
      * @throws {TS.InvalidOperationException}
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      public decrypt(cipherDataByteArray: Array<number>): Array<number>
      {
        TS.Utils.checkUByteArrayParameter("cipherDataByteArray", cipherDataByteArray, "TS.Security.AES_CFB.encrypt");

        if ((this.segmentSizeInBit % 8) != 0)
        {
          throw new TS.InvalidOperationException("The 'decrypt' function which uses a byte array as input parameter can only be use if the segment size aligns with 8 bit. That means, segment size must be a value which is n * 8, where n is a positive integer > 0. Use the 'decryptBitString' function if the segment size doesn't fit. Error occured in 'TS.Security.AES_CFB.decrypt'.");
        }//END if

        return this.encryptDecryptInternal(cipherDataByteArray, CipherOperationEnum.DECRYPT);
      }



      /**
      * @description Encrypts the data given in argument 'bitString' and returns the encrypted data as bit string. This
      *  function will not work if the 'bitString' doesn't align with the 'segmentSizeInBit'.
      *
      * @param {string} bitString, The plain data as bit string.
      * 
      * @returns {string}, The encrypted data as bit string.
      *
      * @throws {TS.InvalidOperationException}
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
      * @throws {TS.InvalidTypeException}
      */
      public encryptBitString(bitString: string): string
      {
        TS.Utils.checkBitStringParameter("bitString", bitString, "TS.Security.AES_CFB.encryptBitString");

        if ((bitString.length % this.segmentSizeInBit) != 0)
        {
          throw new TS.InvalidOperationException("The input bit string must align with the current segment size. So the bit string must have a length of n * segment size. Where n is a positive integer > 0. Error occured in 'TS.Security.AES_CFB.encryptBitString'.");
        }//END if

        return this.encryptDecryptBitString(bitString, TS.Security.CipherOperationEnum.ENCRYPT);
      }


      /**
      * @description Decrypts the data given in argument 'bitString' and returns the decrypted data as bit string. This
      *  function will not work if the 'bitString' doesn't align with the 'segmentSizeInBit'.
      *
      * @param {string} bitString, The encrypted data as bit string.
      * 
      * @returns {string}, The decrypted data as bit string.
      *
      * @throws {TS.InvalidOperationException}
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
      * @throws {TS.InvalidTypeException}
      */
      public decryptBitString(bitString: string): string
      {
        TS.Utils.checkBitStringParameter("bitString", bitString, "TS.Security.AES_CFB.encryptBitString");

        if ((bitString.length % this.segmentSizeInBit) != 0)
        {
          throw new TS.InvalidOperationException("The input bit string must align with the current segment size. That means the bit string must have a length of n * segment size. Where n is a positive integer > 0. Error occured in 'TS.Security.AES_CFB.decryptBitString'.");
        }//END if

        return this.encryptDecryptBitString(bitString, TS.Security.CipherOperationEnum.DECRYPT);
      }


      /**
      * @description Encrypts or decrypts the data given in argument 'dataByteArray' and returns the processed data as
      *  byte array.
      * 
      * @override
      *
      * @param {Array<number>} dataByteArray
      * @param {CipherOperationEnum} cipherOperation
      * 
      * @returns {Array<number>}, The resulting encrypted or decrypted data as byte array.
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      */
      protected encryptDecryptInternal(dataByteArray: Array<number>, cipherOperation : CipherOperationEnum): Array<number>
      {
        let resultArray: Array<number>;
        let workingByteArray: Array<number>;
        let segmentByteArray: Array<number>;
        let inputState: State;
        let outputSegment: string;
        let inputSegment: string;
        let segmentSizeInByte: number;

        TS.Utils.checkUByteArrayParameter("dataByteArray", dataByteArray, "TS.Security.AES_CFB.encryptDecryptInternal");
        TS.Utils.checkParameter("cipherOperation", cipherOperation, "TS.Security.AES_CFB.encryptDecryptInternal");
        if (!TS.Utils.Assert.isValueOfEnum(cipherOperation, TS.Security.CipherOperationEnum))
        {
          throw new TS.InvalidTypeException("cipherOperation", cipherOperation, "The value of argument 'cipherOperation' must be a valid value from the 'TS.Security.CipherOperationEnum' in function 'TS.Security.AES_CFB.encryptDecryptInternal'.");
        }

        if ((this.segmentSizeInBit % 8) != 0)
        {
          throw new TS.InvalidOperationException("The 'encryptDecryptInternal' function which uses a byte array as input parameter can only be use if the segment size aligns with 8 bit. That means, segment size must be a value which is n * 8, where n is a positive integer > 0. Use the 'encryptDecryptBitString' function if the segment size doesn't fit. Error occured in 'TS.Security.AES_CFB.encryptDecryptInternal'.");
        }//END if

        segmentSizeInByte = this.segmentSizeInBit / 8;
        workingByteArray = dataByteArray.slice();
        inputState = new State(this.IV.toArray());
        resultArray = new Array<number>();

        while (workingByteArray.length > 0)
        {
          segmentByteArray = workingByteArray.slice(0, segmentSizeInByte);

          if (segmentByteArray.length != segmentSizeInByte)
          {
            throw new TS.InvalidOperationException("The given data doesn't align with the current segment size. Cipher operation cancelled. Error occured in 'TS.Security.AES_CFB.encryptDecryptInternal'.");
          }//END if

          inputSegment = TS.Utils.byteArrayToBitString(segmentByteArray);
          workingByteArray = workingByteArray.slice(segmentSizeInByte);
          outputSegment = this.encryptDecryptSegment(inputSegment, cipherOperation, inputState, this.segmentSizeInBit);

          if (cipherOperation == CipherOperationEnum.ENCRYPT)
          {
            inputState = this.createNextInputState(inputState,  outputSegment);
          }//END if
          else
          {
            inputState = this.createNextInputState(inputState, inputSegment);
          }//END else

          resultArray = resultArray.concat(TS.Utils.bitStringToByteArray(outputSegment));
        }//END while

        return resultArray;
      }


      /**
      * @descriptions Encrypts or decrypts the data given in argument 'bitString' by using the operation mode given in
      *  argument 'cipherOperation'.
      *
      * @private
      *
      * @param {string} bitString
      * @param {CipherOperationEnum} cipherOperation
      *
      * @returns {string}, The ecnrypted or decrypted result string
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
      * @throws {TS.InvalidTypeException}
      */
      private encryptDecryptBitString(bitString: string, cipherOperation: CipherOperationEnum): string
      {
        let inputState: State;
        let inputString: string;
        let outputSegment: string;
        let resulString: string;
        let inputSegment: string;
        let workingBitString: string;

        TS.Utils.checkBitStringParameter("bitString", bitString, "TS.Security.AES_CFB.encryptDecryptBitString");
        TS.Utils.checkParameter("cipherOperation", cipherOperation, "TS.Security.AES_CFB.encryptDecryptBitString");
        if (!TS.Utils.Assert.isValueOfEnum(cipherOperation, TS.Security.CipherOperationEnum))
        {
          throw new TS.InvalidTypeException("cipherOperation", cipherOperation, "The value of argument 'cipherOperation' must be a valid value from the 'TS.Security.CipherOperationEnum' in function 'TS.Security.AES_CFB.encryptDecryptBitString'.");
        }

        inputState = new State(this.IV.toArray());
        resulString = "";
        workingBitString = bitString.substr(0);

        while (workingBitString.length >= this.segmentSizeInBit)
        {
          inputSegment = workingBitString.substr(0, this.segmentSizeInBit);
          workingBitString = workingBitString.substr(this.segmentSizeInBit);
          outputSegment = this.encryptDecryptSegment(inputSegment, cipherOperation, inputState, this.segmentSizeInBit);
          resulString += outputSegment;

          if (cipherOperation == CipherOperationEnum.ENCRYPT)
          {
            inputState = this.createNextInputState(inputState, outputSegment);
          }//END if
          else
          {
            inputState = this.createNextInputState(inputState, inputSegment);
          }//END else
        }//END while

        return resulString;
      }


      /**
      * @descriptions Encrypts or decrypts the data segment given in argument 'bitString' by using the operation mode
      *  given in argument 'cipherOperation', the state given in argument 'inputState' and the segment size given in
      *  argument 'segmentSizeInBit'.
      *
      * @private
      *
      * @param {string} bitString
      * @param {CipherOperationEnum} cipherOperation
      * @param {TS.Security.State} inputState
      * @param {number} segmentSizeInBit
      *
      * @returns {string}, The ecnrypted or decrypted result string
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
      * @throws {TS.InvalidTypeException}
      */
      private encryptDecryptSegment(bitString: string, cipherOperation: CipherOperationEnum, inputState: TS.Security.State, segmentSizeInBit: number): string
      {
        let outputState: State;
        let resultString: string;
        let xorString: string;
        let index: number;

        TS.Utils.checkBitStringParameter("bitString", bitString, "TS.Security.AES_CFB.encryptDecryptSegment");
        TS.Utils.checkParameter("cipherOperation", cipherOperation, "TS.Security.AES_CFB.encryptDecryptSegment");
        if (!TS.Utils.Assert.isValueOfEnum(cipherOperation, TS.Security.CipherOperationEnum))
        {
          throw new TS.InvalidTypeException("cipherOperation", cipherOperation, "The value of argument 'cipherOperation' must be a valid value from the 'TS.Security.CipherOperationEnum' in function 'TS.Security.AES_CFB.encryptDecryptSegment'.");
        }
        TS.Utils.checkInstanceOfParameter("inputState", inputState, TS.Security.State, "TS.Security.AES_CFB.encryptDecryptSegment");
        TS.Utils.checkUIntNumberParameter("segmentSizeInBit", segmentSizeInBit, "TS.Security.AES_CFB.encryptDecryptSegment");

        outputState = new State(inputState.toArray());
        outputState.encrypt(this.workingKeyByteArray, this.rounds);
        xorString = TS.Utils.byteArrayToBitString(outputState.toArray());
        xorString = xorString.substr(0, segmentSizeInBit);
        resultString = "";

        for (index = 0; index < segmentSizeInBit; index++)
        {
          resultString += (parseInt(xorString.charAt(index), 2) ^ parseInt(bitString.charAt(index), 2)).toString(2);
        }//END for

        return resultString;
      }


      /**
      * @description Creates a new state form the state given in argument 'state' and the cipher segment given in
      *  argument 'cipherSegment'.
      *
      * @private
      *
      * @param {TS.Security.State} state
      * @param {string} cipherSegment
      *
      * @returns {TS.Security.State}
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
      * @throws {TS.InvalidTypeException}
      */
      private createNextInputState(state: TS.Security.State, cipherSegment: string): TS.Security.State
      {
        let bitString: string;
        let byteString: string;
        let resultArray: Array<number>;

        TS.Utils.checkInstanceOfParameter("state", state, TS.Security.State, "TS.Security.AES_CFB.createNextInputState");
        TS.Utils.checkStringParameter(cipherSegment, cipherSegment, "TS.Security.AES_CFB.createNextInputState");

        bitString = "";
        state.toArray().forEach((value, index, array) => { bitString += TS.Utils.byteToBitString(value); });
        bitString = bitString.substr(this.segmentSizeInBit) + cipherSegment;
        resultArray = new Array<number>();

        while (bitString.length >= 8)
        {
          byteString = bitString.slice(0, 8);
          bitString = bitString.slice(8);
          resultArray.push(parseInt(byteString, 2));
        }//END while

        return new State(resultArray);
      }

    }//END class

  }//END namespace
}//END namespace