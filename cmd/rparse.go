//
//

package main

// grammar:
// a squence of rules
//
// rule  -> phase what orl EOL|EOF
//          what orl EOL|EOF
// phase -> HELO | MFROM | RTO | DATA | MESSAGE
// what  -> ACCEPT | REJECT | STALL
// orl   -> andl [OR orl]
// andl  -> terml [andl]
// terml -> NOT terml
//          ( orl )
//          TLS ON|OFF
//          DNS DNS-OPT[,DNS-OPT]
//          GREETED GREETED-OPT[,GREETED-OPT]
//          ADDRESS|FROM-ADDRESS|TO-ADDRESS ADDR-OPT[,ADDR-OPT]
//          FROM|TO|HELO|HOST arg
// arg   -> VALUE
//          FILENAME
