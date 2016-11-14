/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {
    /**
    * @class TS.Security.Counter
    *
    * @description A counter which returns a maximum of 0xFFFFFFFF <=> 4294967295 distinguish values. The counter can
    *  be used as simple counter which produces integer numbers by consecutive readings of the 'nextCounter' property
    *  or as a state generator by consecutive readings of the 'nextState' property.
    *
    * @extends {TS.Security.Cryptography}
    */
    export class Counter extends TS.Security.Cryptography
    {
      private internalCurrentCounterValue: number;
      private internalInitialCounterValue: number;
      private internalCounterStarted: boolean;
      private internalNonceArray: Array<number>;

      /**
      * @get {Array<number>} nonce, The nonce wich was used or created during construction.
      */
      get nonce(): Array<number>
      {
        return this.internalNonceArray;
      }

      /**
      * @get { TS.Security.State} nextState, The next counter state.
      * 
      * @throws {TS.IndexOutOfRangeException}
      */
      get nextState(): TS.Security.State
      {
        return this.getNextState();
      }

      /**
      * @get { TS.Security.State} nextCounter, The next counter.
      * 
      * @throws {TS.IndexOutOfRangeException}
      */
      get nextCounter(): number
      {
        return this.getNextCounter();
      }


      /**
      * @constructor
      *
      * @description Creates a new counter using the provided 'nonce' value to create the initial value. Setting the
      *  'initialCounter' to 0.
      *
      * @param {Array<number>} nonce, An array of 16 unsigned byte values.
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidOperationException}
      * @throws {TS.ArgumentNullUndefOrEmptyException}
      * @throws {TS.ArgumentOutOfRangeException}
      * @throws {TS.InvalidTypeException}
      */
      constructor(nonce: Array<number>);
      /**
      * @constructor
      *
      * @description Creates a new counter using the provided 'initialCounter' to initialize the counter.
      *
      * @param {number} initialCounter, An unsigned integer in the range of [0..0xFFFFFFFF]
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidOperationException}
      * @throws {TS.ArgumentNullUndefOrEmptyException}
      * @throws {TS.ArgumentOutOfRangeException}
      * @throws {TS.InvalidTypeException}
      */
      constructor(initialCounter: number)
      /**
      * @constructor
      *
      * @description Creates a new counter using a default nonce to initialize the counter. 
      *
      * @param {Array<number>} nonce,
      *
      * @throws {TS.ArgumentNullOrUndefinedException}
      * @throws {TS.InvalidOperationException}
      */
      constructor()
      constructor()
      {
        let index: number;
        let counterByteArray: Array<number>;

        super();

        //
        // The default constructor was called.
        //
        if (arguments.length == 0)
        {
          this.internalNonceArray = this.createNonceArray();
          this.internalCurrentCounterValue = this.internalInitialCounterValue = TS.Utils.byteArrayToUInt(this.internalNonceArray.slice(12));
        }//END if

        if (arguments.length > 0)
        {
          TS.Utils.checkNotEmptyParameter(arguments[0], "nonce | initialCounter", "TS.Security.Counter.constructor");

          //
          // The constructor which provides a nonce array was called.
          //
          if (TS.Utils.Assert.isUnsignedByteArray(arguments[0]))
          {
            if (arguments[0].length != 16)
            {
              throw new TS.ArgumentOutOfRangeException("nonce", arguments[0], "Argument 'nonce' must be a byte array with 16 elements in function 'TS.Security.Counter.constructor'.");
            }//END if
            this.internalNonceArray = arguments[0].slice();
            this.internalCurrentCounterValue = this.internalInitialCounterValue = TS.Utils.byteArrayToUInt(arguments[0].slice(12));
          }//END else if

          //
          // The constructor which provides an initial start value was called.
          //
          else if (TS.Utils.Assert.isUnsignedIntegerNumber(arguments[0]))
          {
            if (arguments[0] > 0xFFFFFFFF)
            {
              throw new TS.ArgumentOutOfRangeException("initialCounter", arguments[0], "Argument 'initialCounter' must not exceed the maximum value of 0xFFFFFFFF in function TS.Security.Counter.constructor.");
            }//END if
            this.internalNonceArray = new Array<number>();
            for (index = 0; index < 12; index++)
            {
              this.internalNonceArray.push(0);
            }//END for
            this.internalNonceArray.concat(TS.Utils.UInt32To4ByteArray(arguments[0]));
            this.internalCurrentCounterValue = this.internalInitialCounterValue = arguments[0];
          }//END else if

          //
          // Invalid call to this constructor.
          //
          else
          {
            throw new TS.InvalidTypeException("nonce | initialCounter", arguments[0], "The argument in the constructor of 'TS.Security.Counter' has an invalid type. Error occured in function TS.Security.Counter.constructor.");
          }//END else
        }//END if

        this.internalCounterStarted = false;
      }


      /**
      * @returns {number}, The next counter value.
      * 
      * @throws {TS.IndexOutOfRangeException}
      */
      private getNextCounter(): number
      {
        if (!this.internalCounterStarted)
        {
          this.internalCounterStarted = true;
          return this.internalInitialCounterValue;
        }//END if

        this.internalCurrentCounterValue++;

        if (this.internalCounterStarted && (this.internalCurrentCounterValue == this.internalInitialCounterValue))
        {
          throw new TS.IndexOutOfRangeException("The current counter exceeded the counter range which is 0xFFFFFFFF different values in function 'TS.Security.Counter.getNext'");
        }//END if

        if (this.internalCurrentCounterValue > 0xFFFFFFFF)
        {
          this.internalCurrentCounterValue = 0;
        }//END if

        return this.internalCurrentCounterValue;
      }


      /**
      * @returns {TS.Security.State} , The next counter state.
      * 
      * @throws {TS.IndexOutOfRangeException}
      */
      private getNextState(): TS.Security.State
      {
        let counterByteArray: Array<number>;

        counterByteArray = TS.Utils.UInt32To4ByteArray(this.getNextCounter());

        return new TS.Security.State(this.internalNonceArray.slice(0, 12).concat(counterByteArray));
      }

      /**
       * @private
       */
      private createNonceArray(): Array<number>
      {
        let rng: TS.Security.RandomNumberGenerator;
        let IV: Array<number>;
        let _resultArray: Array<number>;
        let key: Array<number>;

        IV = [185, 78, 34, 160, 69, 3, 238, 110, 4, 92, 124, 48, 114, 45, 62, 129];
        key = [65, 106, 63, 55, 45, 52, 52, 109, 194, 167, 101, 37, 120, 85, 98, 44]; //"Aj?7-44m§e%xUb,"
        rng = new TS.Security.RandomNumberGenerator(key, IV);
        return rng.next;
      }

    }//END class

  }//END namespace
}//END namespace