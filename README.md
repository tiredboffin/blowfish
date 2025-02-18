Recovery of the Original Blowfish P-table from a Known Expanded P-table
Based on Richard Schroeppel’s [report.pdf](https://www.osti.gov/servlets/purl/1141651)

**Procedure for Recovery**:

To recover the starting P (i.e., pi^KKKk), follow these steps:

1) Set P17 and P18 to 0, and substitute A-D with the pi bits.
2) Encrypt P15 and P16 using the modified P-table. XOR the resulting encryption with P17 and P18 to retrieve the original P17 and P18 values.
3) Continue this process working backwards through the P-table, retrieving values for P13, P14, and so on.
4) XOR away the pi-bits at each step to deduce the key fragment KKKk.
5) From the recovered key fragments, select the longest consistent key as the correct K.

The code is based on the original Blowfish implementation: [blowfish-koc.zip](https://www.schneier.com/wp-content/uploads/2015/12/bfsh-koc.zip).

For license and usage information, please refer to the comments in the blowfish.c file.