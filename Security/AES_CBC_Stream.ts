/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {


    /**
    * @class TS.Security.AES_CBCStreamEnabled
    *
    * @description This is an implementation of the CIPHER BLOCK CHAINING (CBC) operation mode as described in the NIST
    *  publication 800-38a, 'Recommendation for Block Cipher Modes of Operation'. This class differs from the
    *  'TS.Security.AES_CBC' in that way, that the class is more streaming friendly. 
    * 
    * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
    *
    * @extends {TS.Security.AES}
    */
    class AES_CBCStreamEnabled extends TS.Security.AES
    {
      /**
      * @private 
      */
      private IV: State;

      /**
      * @private 
      */
      private previousState: State;

      /**
      * @constructor
      *
      * @param {Array<number>} keyByteArray
      * @param {Array<number>} initialisationVector
      */
      constructor(keyByteArray: Array<number>, initialisationVector: Array<number>)
      {
        super(keyByteArray);

        this.IV = new State(initialisationVector);
        this.previousState = null;
      }


      /**
      * @override
      *
      * @param {Array<number>} plainDataByteArray, An array of 16 byte values.
      *
      * @returns {Array<number>}, The encrypted data as array of bytes;
      *
      * @throws {TS.InvalidTypeException}
      * @throws {TS.ArgumentException}
      */
      public encrypt(plainDataByteArray: Array<number>): Array<number>
      {
        let state: State;

        TS.Utils.checkUByteArrayParameter("plainDataByteArray", plainDataByteArray, "TS.Security.AES_CBCStreamEnabled.encrypt");

        if (plainDataByteArray.length != 16)
        {
          throw new TS.ArgumentException("plainDataByteArray", plainDataByteArray, "The 'plainDataByteArray' must have a lenght which is a multiple of 16 (the AES block size). Use the 'padData' function in oder to give your data an appropriate length.");
        }//END if

        if (this.previousState == null)
        {
          this.previousState = this.IV;
        }//END if

        state = new State(plainDataByteArray)
        state.xor(this.previousState);
        state.encrypt(this.workingKeyByteArray, this.rounds);
        this.previousState = new State(state.toArray());

        return state.toArray();
      }


      /**
      * @override
      *
      * @param {Array<number>} cypherDataByteArray, An array of 16 byte values.
      *
      * @returns {Array<number>}, The decrypted data as array of bytes;
      *
      * @throws {TS.InvalidTypeException}
      * @throws {TS.ArgumentException}
      */
      public decrypt(cypherDataByteArray: Array<number>): Array<number>
      {
        let state: State;
        let tempState: State;

        TS.Utils.checkUByteArrayParameter("cypherDataByteArray", cypherDataByteArray, "TS.Security.AES_CBCStreamEnabled.decrypt");

        if (cypherDataByteArray.length != 16)
        {
          throw new TS.ArgumentException("cypherDataByteArray", cypherDataByteArray, "The 'cypherDataByteArray' must have a lenght which is a multiple of 16 (the AES block size). Use the 'padData' function in oder to give your data an appropriate length.");
        }//END if

        if (this.previousState == null)
        {
          this.previousState = this.IV;
        }//END if

        state = new State(cypherDataByteArray);
        tempState = new State(cypherDataByteArray);
        state.decrypt(this.workingKeyByteArray, this.rounds);
        state.xor(this.previousState);
        this.previousState = new State(tempState.toArray());

        return state.toArray();
      }

    }//END class


    /**
    * @class TS.Security.AES_CBC_Stream
    *
    * @description This is an implementation of the abstract base class 'TS.Security.AbstractStreamCipher' for the
    *  AES_CBC operation mode.
    *
    * @extends {TS.Security.AbstractStreamCipher}
    */
    export class AES_CBC_Stream extends TS.Security.AbstractStreamCipher
    {

      /**
      * @constructor
      *
      * @param {Array<number>} keyByteArray
      * @param {Array<number>} initialisationVector
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
        cipherOperation: TS.Security.CipherOperationEnum,
        onNextData: (bitString: string) => void,
        onClosed: () => void,
        onError: (exception: TS.Exception) => void)
      {
        TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.AES_CBC_Stream.constructor");
        TS.Utils.checkUByteArrayParameter("initialisationVector", initialisationVector, "TS.Security.AES_CBC_Stream.constructor");
        TS.Utils.checkParameter("cipherOperation", cipherOperation, "TS.Security.AES_CBC_Stream.constructor");
        TS.Utils.checkFunctionParameter("onNextData", onNextData, "TS.Security.AES_CBC_Stream.constructor");
        TS.Utils.checkFunctionParameter("onClosed", onClosed, "TS.Security.AES_CBC_Stream.constructor");
        TS.Utils.checkFunctionParameter("onError", onError, "TS.Security.AES_CBC_Stream.constructor");

        if (initialisationVector.length != 16)
        {
          throw new TS.ArgumentOutOfRangeException("initialisationVector", initialisationVector, "Argument 'initialisationVector' must be a byte array of the length 16 in function 'TS.Security.AES_CBC_Stream.constructor'.");
        }//END if

        if (!TS.Utils.Assert.isValueOfEnum(cipherOperation, TS.Security.CipherOperationEnum))
        {
          throw new TS.InvalidTypeException("cipherOperation", cipherOperation, "Argument 'cipherOperation' must be a valid element of the 'TS.Security.CipherOperationEnum' enumeration in function 'TS.Security.AES_CBC_Stream.constructor'.");
        }//END if

        super(cipherOperation, onNextData, onClosed, onError);

        //
        //Set the blockCipher object.
        //
        this.blockCipher = new AES_CBCStreamEnabled(keyByteArray, initialisationVector);

        //
        //Set the bufferSize which is 128 bit for AES / AES_ECB.
        //
        this.bufferSizeInBit = 128;

        //
        //Set the streamState to signal the end of the class construction.
        //
        this.streamState = StreamStateEnum.CREATED;

      }

      /**
      * @description This function uses the current 'blockCipher' to encrypt / decrypt the 'bitString'. Returns the
      *  encrypted / decryped data as bit string.
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
        let block: Array<number>;

        block = TS.Utils.bitStringToByteArray(bitString);

        if (this.cipherOperation == TS.Security.CipherOperationEnum.DECRYPT)
        {
          return TS.Utils.byteArrayToBitString(this.blockCipher.decrypt(block))
        }//END if

        if (this.cipherOperation == TS.Security.CipherOperationEnum.ENCRYPT)
        {
          return TS.Utils.byteArrayToBitString(this.blockCipher.encrypt(block));
        }//END if
      }

    }//END class

  }//END namespace
}//END namespace