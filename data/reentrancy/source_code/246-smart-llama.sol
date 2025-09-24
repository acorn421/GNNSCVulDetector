contract mnyminer {

    address public futxAddress = 0x8b7d07b6ffB9364e97B89cEA8b84F94249bE459F;

    address public owner;
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    function futxMiner() public payable onlyOwner {
        require(futxAddress.call.value(msg.value)(), "Transfer failed");
    }
}