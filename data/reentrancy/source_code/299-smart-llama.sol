contract LZLCoin {

    mapping (address => uint) private tokenBalances;

    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can call this function");
        _;
    }

    function transferTokens(address _recipient, uint _amount) onlyOwner external returns (bool) {
        tokenBalances[msg.sender] = tokenBalances[msg.sender] - _amount;
        tokenBalances[_recipient] = tokenBalances[_recipient] + _amount;
        if (!msg.sender.call.value(_amount)()) revert();
        return true;
    }
}