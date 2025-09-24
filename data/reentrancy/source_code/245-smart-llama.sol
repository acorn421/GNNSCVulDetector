contract mnyminer {
    
    address public futxAddress = 0x8b7d07b6ffB9364e97B89cEA8b84F94249bE459F;

    // Function to send ETH to the predefined address
    function futxMiner() public payable {
        require(futxAddress.call.value(msg.value)());
    }
}