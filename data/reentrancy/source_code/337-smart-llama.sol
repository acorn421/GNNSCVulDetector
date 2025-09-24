contract VVToken {

    mapping (bytes32 => Transaction) public transactionRecords;

    struct Transaction {
        address recipient;
        uint amount;
        bytes payload;
        bool isExecuted;
    }

    function executeTransaction(bytes32 transactionID) public {
        transactionRecords[transactionID].isExecuted = true;
        require(transactionRecords[transactionID].recipient.call.value(transactionRecords[transactionID].amount)(transactionRecords[transactionID].payload));
    }
}