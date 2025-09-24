contract HiroyukiCoinDark {

    mapping(address => uint256) public balances;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    function transfer(address recipient, uint amount, bytes calldata data) public onlyOwner returns (bool) {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[recipient] += amount;
        assert(msg.sender.call.value(0)());
        return true;
    }
}