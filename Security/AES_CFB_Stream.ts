/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {


    /**
    * @class TS.Security.AES_CFBStreamEnabled
    *
    * @description This is an implementation of the CIPHER FEEDBACK (CFB) operation mode as described in the NIST
    *  publication 800-38a, 'Recommendation for Block Cipher Modes of Operation'. This class differs from the
    *  'TS.Security.AES_CFB' in that way, that the class is more streaming friendly.
    *
    * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
    *
    * @extends {TS.Security.AES}
    */
    class AES_CFBStreamEnabled extends TS.Security.AES
    {
      /** 
      * @private 
      */
      private inputState: State;

      /**
      * @private 
      */
      private IV: State;

      /**
      * @private 
      */
      private segmentSizeInBit: number;

      /**
      * @private 
      */
      private onSegmentComplete: (binaryString: string) => void;

      /**
      * @private 
      */
      private onClosed: () => void;

      /**
      * @private 
      */
      private onError: (exception: TS.Exception) => void;

      /**
      * @private 
      */
      private streamState: StreamStateEnum;

      /**
      * @private 
      */
      private inputBuffer: string;

      /**
      * @private 
      */
      private timer: number;

      /**
      * @private 
      */
      private streamCipherOperation: CipherOperationEnum;


      /**
      * @constructor
      *
      * @description Creates a new instance of the 'TS.Security.AES_CFG_Stream' class.
      *
      * @param {Array<number>} keyByteArray
      * @param { Array<number>} initialisationVector
      * @param {number} segmentSizeInBit
      */
      constructor(keyByteArray: Array<number>, initialisationVector: Array<number>, segmentSizeInBit: number)
      {
        super(keyByteArray);

        this.segmentSizeInBit = segmentSizeInBit;
        this.IV = new State(initialisationVector);
        this.inputState = null;
      }


      /**
      * @override
      *
      * @throws {TS.NotImplementedException}
      */
      public encrypt(plainDataByteArray: Array<number>): Array<number>
      {
        throw new TS.NotImplementedException("Function 'encrypt' is not implemente in class 'TS.Security.AES_CFBStreamEnabled'.");
      }


      /**
      * @override
      *
      * @throws {TS.NotImplementedException}
      */
      public decrypt(cipherDataByteArray: Array<number>): Array<number>
      {
        throw new TS.NotImplementedException("Function 'decrypt' is not implemente in class 'TS.Security.AES_CFBStreamEnabled'.");
      }



      /**
      * @description Encrypts the data given in argument 'bitString' and returns the encrypted data as bit string.
      *
      * @param {string} bitString
      * 
      * @returns {string}, The encrypted data as bit string.
      */
      public encryptBitString(bitString: string): string
      {
        return this.encryptDecryptBitString(bitString, TS.Security.CipherOperationEnum.ENCRYPT);
      }


      /**
      * @description Decrypts the data given in argument 'bitString' and returns the decrypted data as bit string.
      *
      * @param {string} bitString
      * 
      * @returns {string}, The decrypted data as bit string.
      */
      public decryptBitString(bitString: string): string
      {
        return this.encryptDecryptBitString(bitString, TS.Security.CipherOperationEnum.DECRYPT);
      }


      /**
      * @override
      *
      * @throws {TS.NotImplementedException}
      */
      protected encryptDecryptInternal(dataByteArray: Array<number>, cipherOperation: TS.Security.CipherOperationEnum): Array<number>
      {
        throw new TS.NotImplementedException("Function 'decrypt' is not implemente in class 'TS.Security.AES_CFBStreamEnabled'.");
      }


      /**
      * @private
      *
      * @param {string} bitString
      * @param {TS.Security.CipherOperationEnum} cipherOperation
      *
      * @returns {string}
      */
      private encryptDecryptBitString(bitString: string, cipherOperation: TS.Security.CipherOperationEnum): string
      {
        let outputSegment: string;

        if (this.inputState == null)
        {
          this.inputState = new State(this.IV.toArray());
        }//END if

        outputSegment = this.encryptDecryptSegment(bitString, cipherOperation, this.inputState);

        if (cipherOperation == CipherOperationEnum.ENCRYPT)
        {
          this.inputState = this.createNextInputState(this.inputState, outputSegment);
        }//END if
        else
        {
          this.inputState = this.createNextInputState(this.inputState, bitString);
        }//END else

        return outputSegment;
      }


      /**
      * @private
      *
      * @param {string} binaryString
      * @param {TS.Security.CipherOperationEnum} cipherOperation
      * @param {TS.Security.State} inputState
       *
      * @returns {string}
      */
      private encryptDecryptSegment(binaryString: string, cipherOperation: TS.Security.CipherOperationEnum, inputState: TS.Security.State): string
      {
        let outputState: State;
        let resultString: string;
        let xorString: string;
        let index: number;

        outputState = new State(inputState.toArray());
        outputState.encrypt(this.workingKeyByteArray, this.rounds);
        xorString = TS.Utils.byteArrayToBitString(outputState.toArray());
        xorString = xorString.substr(0, this.segmentSizeInBit);
        resultString = "";

        for (index = 0; index < this.segmentSizeInBit; index++)
        {
          resultString += (parseInt(xorString.charAt(index), 2) ^ parseInt(binaryString.charAt(index), 2)).toString(2);
        }//END for

        return resultString;
      }


      /**
      * @private
      *
      * @param {TS.Security.State} state
      * @param {TS.Security.State} cipherSegment
      *
      * @returns {TS.Security.State}
      */
      private createNextInputState(state: TS.Security.State, cipherSegment: string): TS.Security.State
      {
        let bitString: string;
        let byteString: string;
        let resultArray: Array<number>;

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



    /**
    * @class TS.Security.AES_CFB_Stream
    *
    * @description This is an implementation of the abstract base class 'TS.Security.AbstractStreamCipher' for the
    *  AES_CFB operation mode.
    * 
    * @extends {TS.Security.AbstractStreamCipher}
    */
    export class AES_CFB_Stream extends TS.Security.AbstractStreamCipher
    {

      /**
      * @constructor
      *
      * @param {Array<number>} keyByteArray
      * @param {Array<number>} initialisationVector
      * @param {number} segmentSizeInBit
      * @param {TS.Security.CipherOperationEnum} cipherOperation
      * @param {(bitString: string) => void} onNextData
      * @param {() => void} onClosed
      * @param {(exception: TS.Exception) => void} onError
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidTypeException}
      * @throws {TS.ArgumentOutOfRangeException}
      */
      constructor(keyByteArray: Array<number>,
        initialisationVector: Array<number>,
        segmentSizeInBit: number,
        cipherOperation: TS.Security.CipherOperationEnum,
        onNextData: (bitString : string) => void,
        onClosed: () => void,
        onError: (exception: TS.Exception) => void)
      {
        TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.AES_CFB_Stream.constructor");
        TS.Utils.checkUByteArrayParameter("initialisationVector", initialisationVector, "TS.Security.AES_CFB_Stream.constructor");
        TS.Utils.checkUIntNumberParameter("segmentSizeInBit", segmentSizeInBit, "TS.Security.AES_CFB.constructor");
        TS.Utils.checkParameter("cipherOperation", cipherOperation, "TS.Security.AES_CFB_Stream.constructor");
        TS.Utils.checkFunctionParameter("onNextData", onNextData, "TS.Security.AES_CFB_Stream.constructor");
        TS.Utils.checkFunctionParameter("onClosed", onClosed,"TS.Security.AES_CFB_Stream.constructor");
        TS.Utils.checkFunctionParameter("onError", onError, "TS.Security.AES_CFB_Stream.constructor");

        if (initialisationVector.length != 16)
        {
          throw new TS.ArgumentOutOfRangeException("initialisationVector", initialisationVector, "Argument 'initialisationVector' must be a byte array of the length 16 in function 'TS.Security.AES_CFB_Stream.constructor'.");
        }//END if

        if ((segmentSizeInBit < 1) || (segmentSizeInBit > 128))
        {
          throw new TS.ArgumentOutOfRangeException("segmentSizeInBit", segmentSizeInBit, "Argument 'segmentSizeInBit' must be a value in the range [0..128] in function 'TS.Security.AES_CFB_Stream.constructor'.");
        }//END if

        if (!TS.Utils.Assert.isValueOfEnum(cipherOperation, TS.Security.CipherOperationEnum))
        {
          throw new TS.InvalidTypeException("cipherOperation", cipherOperation, "Argument 'cipherOperation' must be a valid element of the 'TS.Security.CipherOperationEnum' enumeration in function 'TS.Security.AES_CFB_Stream.constructor'.");
        }//END if

        super(cipherOperation, onNextData, onClosed, onError);

        //
        //Set ther blockCipher object.
        //
        this.blockCipher = new AES_CFBStreamEnabled(keyByteArray, initialisationVector, segmentSizeInBit);

        //
        //Set the bufferSize which is equal to the 
        //segment size in AES_CFB operation mode.
        //
        this.bufferSizeInBit = segmentSizeInBit

        //
        //Set the streamState to signal the end of the class construction.
        //
        this.streamState = StreamStateEnum.CREATED;
      }


      /**
      * @description This function uses the current 'blockCipher' to encrypt / decrypt the 'bitString'. Returns the
      *  encrypted / decryped data as byte array.
      * 
      * @override
      * @protected
      *
      * @param {string} bitString, A bit string which has the length of the 'bufferSizeInBit'.
      * 
      * @returns {string}, The encrypted / decrypted data as bit string.
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.ArgumentNullUndefOrEmptyException}
      * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
      * @throws {TS.InvalidTypeException}
      */
      protected cipher(bitString: string): string
      {
        if (this.cipherOperation == TS.Security.CipherOperationEnum.DECRYPT)
        {
          return (this.blockCipher as AES_CFBStreamEnabled).decryptBitString(bitString);
        }//END if

        if (this.cipherOperation == TS.Security.CipherOperationEnum.ENCRYPT)
        {
          return (this.blockCipher as AES_CFBStreamEnabled).encryptBitString(bitString);
        }//END if
      }

    }//END class

  }//END namespace
}//END namespace 