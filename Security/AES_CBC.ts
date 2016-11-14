/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {

    /**
    * @class TS.Security.AES_CBC
    *
    * @description This is an implementation of the CIPHER BLOCK CHAINING (CBC) operation mode as described in the NIST
    *  publication 800-38a, 'Recommendation for Block Cipher Modes of Operation'.
    *
    * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
    */
    export class AES_CBC extends AES
    {
      /** 
      * @private 
      */
      private IV: State;

      /**
      * @constructor
      *
      * @description Creates a new AES_CBC instance with the key given in argument 'keyByteArray' and the initialisation
      *  vector given in argument 'initialisationVector'. The 'keyByteArray' must have a total length of 128, 192 or
      *  256 bits. That means the 'keyByteArray' array must have a length of either 16, 24 or 32. Using a key which
      *  doesn't comply with that rule will raise an exception. The initialisation vector must be an array of unsigned
      *  byte values with a total of 16 elements.
      * 
      * @param {Array<number>} keyByteArray, an array of [16 | 24 | 32] byte holding the key.
      * @param {Array<number>} initialisationVector, array of 16 unsigned byte values.
      * 
      * @throws {TS.InvalidOperationException}
      * @throws {TS.InvalidTypeException}
      * @throws {TS.ArgumentOutOfRangeException}
      */
      constructor(keyByteArray: Array<number>, initialisationVector: Array<number>)
      {
        TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.AES_CBC.constructor");
        TS.Utils.checkUByteArrayParameter("initialisationVector", initialisationVector, "TS.Security.AES_CBC.constructor");

        if (initialisationVector.length != 16)
        {
          throw new TS.ArgumentOutOfRangeException("initialisationVector", initialisationVector, "Argument 'initialisationVector' must be a byte array of the length 16 in function 'TS.Security.AES_CBC.constructor'.");
        }//END if

        super(keyByteArray);

        this.IV = new State(initialisationVector);
      }


      /**
      * @override
      *
      * @param {Array<number>} plainDataByteArray
      *
      * @returns {Array<number>}, The encrypted data as byte array.
      *
      * @throws {TS.InvalidTypeException}
      * @throws {TS.ArgumentException}
      */
      public encrypt(plainDataByteArray: Array<number>): Array<number>
      {
        let index: number;
        let state: State;
        let previousState: State;
        let resultByteArray: Array<number>;

        TS.Utils.checkUByteArrayParameter("plainDataByteArray", plainDataByteArray, "TS.Security.AES_CBC.encrypt");

        if ((plainDataByteArray.length % 16) != 0)
        {
          throw new TS.ArgumentException("plainDataByteArray", plainDataByteArray, "The 'plainDataByteArray' must have a lenght which is a multiple of 16 (the AES block size). Use the 'padData' function in oder to give your data an appropriate length.");
        }//END if

        index = 0;
        previousState = this.IV;
        resultByteArray = new Array<number>();

        while (index * 16 < plainDataByteArray.length)
        {
          state = new State(plainDataByteArray.slice(index * 16, (index + 1) * 16))
          state.xor( previousState);
          state.encrypt(this.workingKeyByteArray, this.rounds);
          resultByteArray = resultByteArray.concat(state.toArray());
          previousState = new State(state.toArray());
          index++;
        }//END while

        return resultByteArray;
      }


      /**
      * @override
      *
      * @param {Array<number>} cypherDataByteArray
      *
      * @returns {Array<number>}, The decrypted data as byte array.
      *
      * @throws {TS.InvalidTypeException}
      * @throws {TS.ArgumentException}
      */
      public decrypt(cypherDataByteArray: Array<number>): Array<number>
      {
        let index: number;
        let state: State;
        let previousState: State;
        let resultByteArray: Array<number>;

        TS.Utils.checkUByteArrayParameter("cypherDataByteArray", cypherDataByteArray, "TS.Security.AES_CBC.decrypt");

        if ((cypherDataByteArray.length % 16) != 0)
        {
          throw new TS.ArgumentException("cypherDataByteArray", cypherDataByteArray, "The 'cypherDataByteArray' must have a lenght which is a multiple of 16 (the AES block size). Use the 'padData' function in oder to give your data an appropriate length.");
        }//END if

        index = 0;
        previousState = this.IV;
        resultByteArray = new Array<number>();

        while (index * 16 < cypherDataByteArray.length)
        {
          state = new State(cypherDataByteArray.slice(index * 16, (index + 1) * 16))
          state.decrypt(this.workingKeyByteArray, this.rounds);
          state.xor(previousState);
          resultByteArray = resultByteArray.concat(state.toArray());
          previousState = new State(cypherDataByteArray.slice(index * 16, (index + 1) * 16));
          index++;
        }//END while

        return resultByteArray;
      }

    }//END class

  }//END module
}//END module