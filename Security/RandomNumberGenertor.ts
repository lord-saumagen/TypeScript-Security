/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {


    /**
    * @class TS.Security.RandomNumberGenerator
    *
    * @description This class is an implements of the Random Number Generator as described in the NIST publication:
    *  'NIST Recommended Random Number Generator Based On ANSI X9.31 Appendix A.2.4'.
    * 
    * @see {@link http://csrc.nist.gov/groups/STM/cavp/documents/rng/931rngext.pdf | NIST}
    */
    export class RandomNumberGenerator extends TS.Security.Cryptography
    {
      private aes : TS.Security.AES
      private state: TS.Security.State;

      /**
      * @description Returns the next array of 16 random bytes.
      */
      public get next() : Array<number>
      {
        return this.createNext();
      }


      /**
      * @constructor
      *
      * @description Create a new RandomNumberGenerator instance with the key given in argument 'keyByteArray'. The
      *  'keyByteArray' must have a total length of 128, 192 or 256 bits. That means the 'keyByteArray' array must have
      *   a length of either 16, 24 or 32. Using a key which doesn't comply with that rule will raise an exception. The
      *   initialisationVector must be an array of 16 byte values which should show a high level of entropy.
      * 
      * @param {Array<number>} keyByteArray
      * @param {Array<number>} initialisationVector, An array of 16 byte holding the initalisation vector.
      * 
      * @throws {TS.ArgumentException}
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.ArgumentOutOfRangeException}
      */
      constructor(keyByteArray: Array<number>,  initialisationVector: Array<number>)
      {

        TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.RandomNumberGenerator.constructor");
        TS.Utils.checkUByteArrayParameter("initialisationVector", initialisationVector, "TS.Security.RandomNumberGenerator.constructor");

        if (initialisationVector.length != 16)
        {
          throw new TS.ArgumentOutOfRangeException("initialisationVector", initialisationVector, "Argument 'initialisationVector' must be a byte array of the length 16 in function 'TS.Security.RandomNumberGenerator.constructor'.");
        }//END if

        super();

        this.aes = new TS.Security.AES(keyByteArray);
        this.state = new TS.Security.State(initialisationVector);
      }


      /**
      * @description Creates and returns the next array of 16 random bytes.
      * 
      * @returns {Array<number>} , An array of 16 random bytes.
      */
      private createNext(): Array<number>
      {
        let intermediateState: State;
        let resultState: State;
        let dateTimeByteArry: Array<number>

        dateTimeByteArry = TS.Security.padData(TS.Utils.UIntToByteArray(new Date().valueOf()));
        intermediateState = new State(this.aes.encrypt(dateTimeByteArry));
        intermediateState.xor(this.state);
        resultState = new State(this.aes.encrypt(intermediateState.toArray()));
        intermediateState.xor(resultState);
        this.state = new State(this.aes.encrypt(intermediateState.toArray()));
        return resultState.toArray();
      }

    }//END class

  }//END namespace
}//END namespace