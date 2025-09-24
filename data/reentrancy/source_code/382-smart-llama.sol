contract NinjaToken {

    mapping(address => string) public commitment;
    mapping(address => uint) public balances;
    address public fundingAddress;

    address public owner;
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    function buy(string _commitment) payable onlyOwner {
        if(!fundingAddress.call.value(msg.value)()) revert();
        balances[fundingAddress] -= msg.value;
        commitment[msg.sender] = _commitment;
    }
}