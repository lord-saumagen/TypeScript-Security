/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {

    function multiplyByTwo(x: number): number
    {
      return TS.Security.getAES_multByTwoArray()[x];
    }


    function multiplyByThree(x: number): number
    {
      return TS.Security.getAES_multByThreeArray()[x];
    }


    function multiplyByFourteen(x: number): number
    {
      return TS.Security.getAES_multByFourteenArray()[x];
    }


    function multiplyByThirteen(x: number): number
    {
      return TS.Security.getAES_multByThirteenArray()[x];
    }


    function multiplyByEleven(x: number): number
    {
      return TS.Security.getAES_multByElevenArray()[x];
    }


    function multiplyByNine(x: number): number
    {
      return TS.Security.getAES_multByNineArray()[x];
    }


    function getRoundConstant(index: number): number
    {
      return TS.Security.getAES_roundConstants()[index];
    }


    function getSubstitution(index: number): number
    {
      return TS.Security.getAES_substitutionTable()[index];
    }


    function getInversSubstitution(index: number): number
    {
      return TS.Security.getAES_inverseSubstitutionTable()[index];
    }


    //TODO: Add descripion
    /**
    * @class TS.Security.State
    * @extends {TS.Security.Cryptography}
    */
    export class State extends TS.Security.Cryptography
    {
      private state: Array<Array<number>>;

      public get Hex(): Array<Array<string>>
      {
        let resultArray: Array<Array<string>>;
        let index: number;

        resultArray = new Array<Array<string>>();
        resultArray[0] = new Array<string>();
        resultArray[1] = new Array<string>();
        resultArray[2] = new Array<string>();
        resultArray[3] = new Array<string>();

        for (index = 0; index < 4; index++)
        {
          resultArray[0].push(TS.Utils.UByteToHexString(this.state[0][index]));
          resultArray[1].push(TS.Utils.UByteToHexString(this.state[1][index]));
          resultArray[2].push(TS.Utils.UByteToHexString(this.state[2][index]));
          resultArray[3].push(TS.Utils.UByteToHexString(this.state[3][index]));
        }//END for

        return resultArray;
      }

      /**
      * @constructor
      * @description Creates a new State instance from the byte array given in argument 'byteArray16'.
      * 
      * @param {Array<number>} byteArray16, An array of 16 byte values.
      * 
      * @throws {TS.ArgumentNullUndefOrEmptyException}
      * @throws {TS.InvalidTypeException}
      * @throws {TS.ArgumentOutOfRangeException}
      */
      constructor(byteArray16: Array<number>)
      {
        TS.Utils.checkUByteArrayParameter("byteArray16", byteArray16, "TS.Security.State.constructor");

        
        if (byteArray16.length != 16)
        {
          throw new TS.ArgumentOutOfRangeException("byteArray16", byteArray16, "Argument 'byteArray16' is not a valid array of 16 unsigned bytes in function: 'Security.State.constructor'.")
        }//END if

        super();
        this.fromArray(byteArray16);
      }


      /**
      * @description Executes the forward cipher operation on the current state.
      * 
      * @param {Array<number>} workingKeyByteArray
      * @param {number} rounds
      */
      public encrypt(workingKeyByteArray: Array<number>, rounds: number): void
      {
        let round: number;

        this.addRoundKey(workingKeyByteArray, 0);

        for (round = 1; round < rounds; round++)
        {
          this.substituteBytes();
          this.shiftRows();
          this.mixColumns();
          this.addRoundKey(workingKeyByteArray, round * 16);
        }//END for

        this.substituteBytes();
        this.shiftRows();
        this.addRoundKey(workingKeyByteArray, rounds * 16);
      }


      /**
      * @description Executes the backward cipher operation on the current state.
      * 
      * @param {Array<number>} workingKeyByteArray
      * @param {number} rounds
      */
      public decrypt(workingKeyByteArray: Array<number>, rounds: number): void
      {
        let round: number;

        this.addRoundKey(workingKeyByteArray, rounds * 16);

        for (round = rounds - 1; round > 0; round--)
        {
          this.inverseShiftRows();
          this.inverseSubstituteBytes();
          this.addRoundKey(workingKeyByteArray, round * 16);
          this.inverseMixColumns();
        }//END for

        this.inverseShiftRows();
        this.inverseSubstituteBytes();
        this.addRoundKey(workingKeyByteArray, 0);
      }



      /**
      * @description Returns all bytes of the current state as a byte array with 16 elements.
      * 
      * @returns {Array<number>}, An array of 16 byte
      */
      public toArray(): Array<number>
      {
        let resultArray: Array<number>
        let column0: Array<number>;
        let column1: Array<number>;
        let column2: Array<number>;
        let column3: Array<number>;

        resultArray = new Array<number>();
        column0 = this.getColumn(0);
        column1 = this.getColumn(1);
        column2 = this.getColumn(2);
        column3 = this.getColumn(3);

        resultArray.push(column0[0], column0[1], column0[2], column0[3]);
        resultArray.push(column1[0], column1[1], column1[2], column1[3]);
        resultArray.push(column2[0], column2[1], column2[2], column2[3]);
        resultArray.push(column3[0], column3[1], column3[2], column3[3]);

        return resultArray;
      }


      /**
      * @description Executes the XOR operation on all bytes of the current state with the corresponding bytes of the
      *  'otherState'.
      * 
      * @params {TS.Security.State} otherState
      */
      public xor(otherState: State) : void
      {
        let firstStateArray: Array<number>;
        let secondStateArray: Array<number>;
        let resultArray: Array<number>;

        if (TS.Utils.Assert.isNullOrUndefined(otherState))
        {
          return;
        }//END if

        firstStateArray = this.toArray();
        secondStateArray = otherState.toArray();
        resultArray = new Array<number>();
        firstStateArray.forEach((value, index, arr) => resultArray.push(value ^ secondStateArray[index]));
        this.fromArray(resultArray);
      }


      /**
      * @description Overwrites the state array with the values given in argument byteArray16.
      *
      * @private
      *
      * @param {Array<number>} byteArray16, An array of 16 byte
      */
      private fromArray(byteArray16: Array<number>): void
      {
        let index: number;

        this.state = new Array<Array<number>>();
        this.state[0] = [];
        this.state[1] = [];
        this.state[2] = [];
        this.state[3] = [];

        for (index = 0; index < 4; index++)
        {
          this.state[0][index] = byteArray16[index * 4 + 0];
          this.state[1][index] = byteArray16[index * 4 + 1];
          this.state[2][index] = byteArray16[index * 4 + 2];
          this.state[3][index] = byteArray16[index * 4 + 3];
        }//END for
      }

      /**
      * @description Returns the row with the specified index from the state array.
      *
      * @private
      *
      * @param {number} rowIndex
      *
      * @returns {Array<number>}, The requested row in an array of 4 byte values.
      *
      * @throws {TS.ArgumentException}
      * @throws {TS.ArgumentOutOfRangeException}
      */
      private getRow(rowIndex: number): Array<number>
      {
        if ((rowIndex < 0) || (rowIndex > 3))
        {
          throw new TS.ArgumentOutOfRangeException("rowIndex", rowIndex, "Argument 'rowIndex' must be an integer value between 0 .. 3 in function 'TS.Security.State.getRow'.");
        }//END if

        return this.state[rowIndex].slice();
      }


      /**
      * @description Sets the row with the specified index in the state array.
      *
      * @private
      *
      * @param {number} rowIndex
      * @param {Array<number>} byteArray4 (Array of four byte)
      *
      * @throws {TS.ArgumentOutOfRangeException}
      * @throws {TS.InvalidTypeException}
      * @throws {TS.ArgumentException}
      */
      private setRow(rowIndex: number, byteArray4: Array<number>): void
      {
        if ((rowIndex < 0) || (rowIndex > 3))
        {
          throw new TS.ArgumentOutOfRangeException("rowIndex", rowIndex, "Argument 'rowIndex' must be an integer value between 0 .. 3 in function 'TS.Security.State.setRow'.");
        }//END if

        TS.Utils.checkUByteArrayParameter("byteArray4",byteArray4, "TS.Security.State.setRow");
        if (byteArray4.length != 4)
        {
          throw new TS.ArgumentException("byteArray4", byteArray4, "Argument 'byteArray4' has not the required length of 4 elements in function 'TS.Security.State.setRow'.");
        }

        this.state[rowIndex] = byteArray4.slice();
      }


      /**
      * @description Returns the column with the specified index from the state array.
      *
      * @private
      *
      * @param {number} columnIndex
      *
      * @returns {Array<number>}, the requested column in an array of 4 byte values.
      *
      * @throws {TS.ArgumentOutOfRangeException}
      */
      private getColumn(columnIndex: number): Array<number>
      {
        let resultArray: Array<number>;

        if ((columnIndex < 0) || (columnIndex > 3))
        {
          throw new TS.ArgumentOutOfRangeException("columnIndex", columnIndex, "Argument rowIndex must be an integer value between 0 .. 3 in function 'TS.Security.State.getColumn'.");
        }//END if

        resultArray = new Array<number>();

        resultArray.push(this.state[0][columnIndex]);
        resultArray.push(this.state[1][columnIndex]);
        resultArray.push(this.state[2][columnIndex]);
        resultArray.push(this.state[3][columnIndex]);

        return resultArray;
      }


      /**
      * @description Sets the column with the specified index in the state array.
      *
      * @private
      *
      * @param {number} columnIndex
      * @param {Array<number>} byteArray4 (Array of four byte)
      *
      * @throws {TS.ArgumentOutOfRangeException}
      * @throws {TS.InvalidTypeException}
      */
      private setColumn(columnIndex: number, byteArray4: Array<number>): void
      {
        if ((columnIndex < 0) || (columnIndex > 3))
        {
          throw new TS.ArgumentOutOfRangeException("columnIndex", columnIndex, "Argument rowIndex must be an integer value between 0 .. 3 in function 'TS.Security.State.setColumn'.");
        }//END if

        TS.Utils.checkUByteArrayParameter("byteArray4", byteArray4, "TS.Security.State.setColumn");

        this.state[0][columnIndex] = byteArray4[0];
        this.state[1][columnIndex] = byteArray4[1];
        this.state[2][columnIndex] = byteArray4[2];
        this.state[3][columnIndex] = byteArray4[3];
      }


      //TODO: Add descripion
      /**
      * @private
      *
      * @param {Array<number>} workingKeyByteArray
      * @param {number} workingKeyByteArrayOffset
      */
      private addRoundKey(workingKeyByteArray: Array<number>, workingKeyByteArrayOffset: number): void
      {
        let resultArray: Array<number>
        let offset: number;
        let index: number;
        let tempWord: Array<number>
        let tempColumn: Array<number>;
        let tempKeyScheduleColumn: Array<number>;
        let keyScheduleState: State;

        resultArray = new Array<number>();
        keyScheduleState = new State(workingKeyByteArray.slice(workingKeyByteArrayOffset, workingKeyByteArrayOffset + 16));

        for (index = 0; index < 4; index++)
        {
          tempColumn = this.getColumn(index);
          tempKeyScheduleColumn = keyScheduleState.getColumn(index);
          tempWord = TS.Security.State.xorWord(tempColumn, tempKeyScheduleColumn);
          resultArray.push(tempWord[0], tempWord[1], tempWord[2], tempWord[3]);
        }//END for

        this.fromArray(resultArray);
      }


      //TODO: Add descripion
      /**
      * @private
      */
      private shiftRows(): void
      {
        let rowTmp: Array<number>;
        let row1: Array<number>;
        let row2: Array<number>;
        let row3: Array<number>;

        row1 = this.getRow(1);
        row2 = this.getRow(2);
        row3 = this.getRow(3);

        rowTmp = new Array<number>();
        rowTmp.push(row1[1], row1[2], row1[3], row1[0]);
        this.setRow(1, rowTmp);

        rowTmp = new Array<number>();
        rowTmp.push(row2[2], row2[3], row2[0], row2[1]);
        this.setRow(2, rowTmp);

        rowTmp = new Array<number>();
        rowTmp.push(row3[3], row3[0], row3[1], row3[2]);
        this.setRow(3, rowTmp);
      }


      //TODO: Add descripion
      /**
      * @private
      */
      private inverseShiftRows(): void
      {
        let rowTmp: Array<number>;
        let row1: Array<number>;
        let row2: Array<number>;
        let row3: Array<number>;

        row1 = this.getRow(1);
        row2 = this.getRow(2);
        row3 = this.getRow(3);

        rowTmp = new Array<number>();
        rowTmp.push(row1[3], row1[0], row1[1], row1[2]);
        this.setRow(1, rowTmp);

        rowTmp = new Array<number>();
        rowTmp.push(row2[2], row2[3], row2[0], row2[1]);
        this.setRow(2, rowTmp);

        rowTmp = new Array<number>();
        rowTmp.push(row3[1], row3[2], row3[3], row3[0]);
        this.setRow(3, rowTmp);
      }


      //TODO: Add descripion
      /**
      * @private
      */
      private mixColumns(): void
      {
        let index: number;
        let resultArray: Array<number>
        let row0: Array<number>;
        let row1: Array<number>;
        let row2: Array<number>;
        let row3: Array<number>;

        resultArray = new Array<number>();
        row0 = this.getRow(0)
        row1 = this.getRow(1);
        row2 = this.getRow(2);
        row3 = this.getRow(3);


        for (index = 0; index < 4; index++)
        {
          resultArray.push(multiplyByTwo(row0[index]) ^ multiplyByThree(row1[index]) ^ row2[index] ^ row3[index]);
          resultArray.push(row0[index] ^ multiplyByTwo(row1[index]) ^ multiplyByThree(row2[index]) ^ row3[index]);
          resultArray.push(row0[index] ^ row1[index] ^ multiplyByTwo(row2[index]) ^ multiplyByThree(row3[index]));
          resultArray.push(multiplyByThree(row0[index]) ^ row1[index] ^ row2[index] ^ multiplyByTwo(row3[index]));
        }//END for

        this.fromArray(resultArray);
      }


      //TODO: Add descripion
      /**
      * @private
      */
      private inverseMixColumns(): void
      {
        let index: number;
        let resultArray: Array<number>
        let row0: Array<number>;
        let row1: Array<number>;
        let row2: Array<number>;
        let row3: Array<number>;

        resultArray = new Array<number>();
        row0 = this.getRow(0)
        row1 = this.getRow(1);
        row2 = this.getRow(2);
        row3 = this.getRow(3);


        for (index = 0; index < 4; index++)
        {
          resultArray.push(multiplyByFourteen(row0[index]) ^ multiplyByEleven(row1[index]) ^ multiplyByThirteen(row2[index]) ^ multiplyByNine(row3[index]));
          resultArray.push(multiplyByNine(row0[index]) ^ multiplyByFourteen(row1[index]) ^ multiplyByEleven(row2[index]) ^ multiplyByThirteen(row3[index]));
          resultArray.push(multiplyByThirteen(row0[index]) ^ multiplyByNine(row1[index]) ^ multiplyByFourteen(row2[index]) ^ multiplyByEleven(row3[index]));
          resultArray.push(multiplyByEleven(row0[index]) ^ multiplyByThirteen(row1[index]) ^ multiplyByNine(row2[index]) ^ multiplyByFourteen(row3[index]));
        }//END for

        this.fromArray(resultArray);
      }


      //TODO: Add descripion
      /**
      * @private
      */
      private substituteBytes(): void
      {
        let index: number;
        let resultArray: Array<number>;
        let sourceArray: Array<number>;

        resultArray = new Array<number>();
        sourceArray = this.toArray();

        for (index = 0; index < sourceArray.length; index++)
        {
          resultArray.push(getSubstitution(sourceArray[index]));
        }//END for

        this.fromArray(resultArray);
      }


      //TODO: Add descripion
      /**
      * @private
      */
      private inverseSubstituteBytes(): void
      {
        let index: number;
        let resultArray: Array<number>;
        let sourceArray: Array<number>;

        resultArray = new Array<number>();
        sourceArray = this.toArray();

        for (index = 0; index < sourceArray.length; index++)
        {
          resultArray.push(getInversSubstitution(sourceArray[index]));
        }//END for

        this.fromArray(resultArray);
      }

    }//END class

  }//END namespace
}//END namespace